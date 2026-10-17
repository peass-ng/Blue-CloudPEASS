"""Three-valued evaluation of the decidable subset of GCP IAM Conditions (CEL).

Supported: ``&&``, ``||``, ``!``, parentheses, ``==`` / ``!=`` / ``<`` / ``<=`` / ``>`` / ``>=``,
string literals, ``timestamp("...")``, ``.startsWith()`` / ``.endsWith()`` and the attributes
``resource.name``, ``resource.type``, ``resource.service`` and ``request.time``.

``evaluate`` returns True / False when the expression is decided for the given context and None
when it is not (unknown attribute, unsupported function or syntax, missing context). An
attribute can carry several plausible values (e.g. a project referenced by id or by number): a
comparison is only decided when every candidate agrees. Unsupported forms never raise.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_TOKEN = re.compile(r"""\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?P<op>&&|\|\||==|!=|<=|>=|[()!<>.,])|"""
                    r"""(?P<num>\d+)|(?P<id>[A-Za-z_][A-Za-z0-9_]*))""")
_ATTRS = ("resource.name", "resource.type", "resource.service", "request.time")
_CACHE = {}

# resource.type per resource-name shape (as modelled by the GCP effective-permission model).
_TYPES = (
    (re.compile(r"^projects/[^/]+/serviceAccounts/[^/]+$"), "iam.googleapis.com/ServiceAccount"),
    (re.compile(r"^projects/[^/]+/(zones|locations)/[^/]+/instances/[^/]+$"), "compute.googleapis.com/Instance"),
    (re.compile(r"^projects/[^/]+/locations/[^/]+/clusters/[^/]+$"), "container.googleapis.com/Cluster"),
    (re.compile(r"^projects/[^/]+/secrets/[^/]+$"), "secretmanager.googleapis.com/Secret"),
    (re.compile(r"^projects/[^/]+$"), "cloudresourcemanager.googleapis.com/Project"),
    (re.compile(r"^folders/[^/]+$"), "cloudresourcemanager.googleapis.com/Folder"),
    (re.compile(r"^organizations/[^/]+$"), "cloudresourcemanager.googleapis.com/Organization"),
)


class _Unsupported(Exception):
    pass


def _tokens(expr):
    out, pos = [], 0
    expr = str(expr or "")
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise _Unsupported(expr[pos:pos + 20])
        pos = m.end()
        kind = m.lastgroup
        value = m.group(kind)
        if kind == "str":
            value = bytes(value[1:-1], "utf-8").decode("unicode_escape")
        out.append((kind, value))
    return out


class _Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self, value=None):
        if self.i >= len(self.t):
            return None
        tok = self.t[self.i]
        return tok if value is None or tok[1] == value and tok[0] == "op" else None

    def take(self, value=None):
        tok = self.peek(value)
        if tok is None:
            raise _Unsupported(value or "eof")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i != len(self.t):
            raise _Unsupported("trailing")
        return node

    def or_(self):
        node = self.and_()
        while self.peek("||"):
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek("&&"):
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.peek("!"):
            self.take()
            return ("not", self.not_())
        return self.cmp()

    def cmp(self):
        left = self.term()
        for op in ("==", "!=", "<=", ">=", "<", ">"):
            if self.peek(op):
                self.take()
                return ("cmp", op, left, self.term())
        return left

    def term(self):
        if self.peek("("):
            self.take()
            node = self.or_()
            self.take(")")
            return self.postfix(node)
        kind, value = self.take()
        if kind == "str":
            return self.postfix(("lit", value))
        if kind == "num":
            return ("lit", int(value))
        if kind != "id":
            raise _Unsupported(value)
        if value in ("true", "false"):
            return ("lit", value == "true")
        if value == "timestamp" and self.peek("("):
            self.take()
            arg = self.take()
            self.take(")")
            if arg[0] != "str":
                raise _Unsupported("timestamp")
            return ("lit", _ts(arg[1]))
        if value in ("resource", "request") and self.peek("."):
            self.take()
            attr = value + "." + self.take()[1]
            if attr not in _ATTRS:
                if self.peek("("):  # resource.matchTag(...), request.auth...: an unsupported function call
                    self.args()
                return self.postfix(("unknown",))
            return self.postfix(("attr", attr))
        raise _Unsupported(value)

    def postfix(self, node):
        while self.peek("."):
            self.take()
            name = self.take()[1]
            if not self.peek("("):
                node = ("unknown",)
                continue
            args = self.args()
            node = ("call", name, node, args) if name in ("startsWith", "endsWith") and len(args) == 1 else ("unknown",)
        return node


    def args(self):
        self.take("(")
        out = []
        while not self.peek(")"):
            out.append(self.or_())
            if self.peek(","):
                self.take()
            elif not self.peek(")"):
                raise _Unsupported("args")
        self.take(")")
        return out


def _ts(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _Unsupported(value) from exc


def compile_condition(expr):
    """Parsed expression tree, or None when the syntax is unsupported (always undecided)."""
    if expr not in _CACHE:
        try:
            _CACHE[expr] = _Parser(_tokens(expr)).parse()
        except (_Unsupported, IndexError, ValueError):
            _CACHE[expr] = None
    return _CACHE[expr]


def uses_resource(expr):
    tree = compile_condition(expr)
    return tree is None or "'resource." in repr(tree) or "('unknown',)" in repr(tree)


def _values(node, ctx):
    """Candidate values of a value node: a tuple, or None when unknown."""
    kind = node[0]
    if kind == "lit":
        return (node[1],)
    if kind == "attr":
        value = ctx.get(node[1])
        if value is None:
            return None
        return tuple(value) if isinstance(value, (list, tuple, set, frozenset)) else (value,)
    return None


def _truth(node, ctx):
    kind = node[0]
    if kind == "lit":
        return node[1] if isinstance(node[1], bool) else None
    if kind == "not":
        value = _truth(node[1], ctx)
        return None if value is None else not value
    if kind in ("and", "or"):
        left, right = _truth(node[1], ctx), _truth(node[2], ctx)
        if kind == "and":
            if left is False or right is False:
                return False
            return True if left is True and right is True else None
        if left is True or right is True:
            return True
        return False if left is False and right is False else None
    if kind == "cmp":
        _, op, a, b = node
        left, right = _values(a, ctx), _values(b, ctx)
        if left is None or right is None:
            return None
        results = set()
        for x in left:
            for y in right:
                try:
                    results.add({"==": x == y, "!=": x != y, "<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op])
                except TypeError:
                    return None
        return results.pop() if len(results) == 1 else None
    if kind == "call":
        _, name, target, args = node
        subject, arg = _values(target, ctx), _values(args[0], ctx)
        if subject is None or arg is None or not all(isinstance(v, str) for v in subject + arg):
            return None
        results = {(s.startswith(a) if name == "startsWith" else s.endswith(a)) for s in subject for a in arg}
        return results.pop() if len(results) == 1 else None
    return None


def evaluate(expr, ctx):
    """True / False when decided, None otherwise."""
    tree = compile_condition(expr)
    return None if tree is None else _truth(tree, ctx)


def now_context(now=None):
    return {"request.time": now or datetime.now(timezone.utc)}


def resource_context(resource, aliases=(), now=None):
    """Context for a resource name as modelled (projects/<id>/..., folders/<n>, ...)."""
    ctx = now_context(now)
    resource = str(resource or "")
    names = [resource] + [a for a in aliases if a and a != resource]
    if resource.startswith("projects/") and "/serviceAccounts/" in resource:
        tail = resource.split("/serviceAccounts/", 1)[1]
        names += ["projects/-/serviceAccounts/" + tail]
    if names and resource and not resource.startswith("//"):
        ctx["resource.name"] = tuple(dict.fromkeys(names))
    for pattern, rtype in _TYPES:
        if pattern.match(resource):
            ctx["resource.type"] = rtype
            ctx["resource.service"] = rtype.split("/", 1)[0]
            break
    return ctx
