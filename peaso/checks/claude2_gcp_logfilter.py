"""Three-valued evaluator for the Cloud Logging query language, used by the claude2_gcp metric predicates.

It is deliberately conservative. A filter is evaluated against synthetic, *incomplete* audit-log events that
represent the change a CIS log-metric control must capture. Every comparison returns True, False or None
(cannot be decided from the synthetic event). Anything the evaluator does not model (unknown functions,
fields absent from the synthetic event, ambiguous case-sensitivity, bare text that is not found) yields None,
so a caller can only conclude "matches" or "does not match" when the language semantics are certain.

Reference: https://cloud.google.com/logging/docs/view/logging-query-language
  * Boolean operators: NOT binds tightest, then OR, then AND (``a AND b OR c`` is ``a AND (b OR c)``).
  * Juxtaposition is an implicit AND; a leading ``-`` is NOT.
  * Comparisons ``= != > < >= <= : =~ !~``; ``field:*`` tests presence; values may be grouped
    with parentheses and AND/OR/NOT.
  * A bare term or quoted string is a global text restriction.
  * Repeated fields match when any element matches.
"""
from __future__ import annotations
import re
from urllib.parse import quote

__all__ = ["FilterError", "parse", "evaluate", "verdict", "audit_event"]


class FilterError(ValueError):
    """The filter could not be parsed with the modeled grammar (treated as uncertain, never as a non-match)."""


OPS = (">=", "<=", "!=", "=~", "!~", "=", ">", "<", ":")
STOP = set(" \t\r\n()\"=!<>:~")
SEVERITY = {"DEFAULT": 0, "DEBUG": 100, "INFO": 200, "NOTICE": 300, "WARNING": 400, "ERROR": 500,
            "CRITICAL": 600, "ALERT": 700, "EMERGENCY": 800}
# Top-level LogEntry members that an Admin Activity audit entry never carries.
ABSENT_ROOTS = frozenset({"jsonPayload", "textPayload", "httpRequest", "json_payload", "text_payload", "http_request"})
MISSING = object()


def _string(text, i):
    out, i = [], i + 1
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        if char == '"':
            return "".join(out), i + 1
        out.append(char)
        i += 1
    raise FilterError("unterminated string")


def tokenize(text):
    tokens, i = [], 0
    while i < len(text):
        char = text[i]
        if char.isspace():
            i += 1
            continue
        if text.startswith("--", i):  # comment to end of line
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if char in "()":
            tokens.append((char, char))
            i += 1
            continue
        if char == '"':
            value, i = _string(text, i)
            tokens.append(("STR", value))
            continue
        op = next((o for o in OPS if text.startswith(o, i)), None)
        if op:
            tokens.append(("OP", op))
            i += len(op)
            continue
        if char == "-" and (not tokens or tokens[-1][0] in ("(", "AND", "OR", "NOT", "NEG", "WORD", "STR", ")")):
            # A leading '-' negates the next term; '-' inside a word is part of it.
            if i + 1 < len(text) and not text[i + 1].isspace():
                tokens.append(("NEG", "-"))
                i += 1
                continue
        segments, raw, current = [], "", ""
        while i < len(text):
            char = text[i]
            if char == '"' and raw.endswith("."):
                value, i = _string(text, i)
                segments.append(value)
                raw += '"' + value + '"'
                current = None
                continue
            if char in STOP:
                break
            if char == "." and current is not None:
                segments.append(current)
                current = ""
            elif char == ".":
                current = ""
            else:
                current = (current or "") + char
            raw += char
            i += 1
        if current:
            segments.append(current)
        if not raw:
            raise FilterError("unexpected character " + repr(text[i]))
        if raw in ("AND", "OR", "NOT"):
            tokens.append((raw, raw))
        else:
            tokens.append(("WORD", raw, tuple(segments)))
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.pos = tokens, 0

    def peek(self, offset=0):
        index = self.pos + offset
        return self.tokens[index] if index < len(self.tokens) else ("EOF", None)

    def take(self, kind=None):
        token = self.peek()
        if kind is not None and token[0] != kind:
            raise FilterError(f"expected {kind}, found {token[0]}")
        self.pos += 1
        return token

    def starts_term(self):
        return self.peek()[0] in ("WORD", "STR", "(", "NOT", "NEG")

    def expression(self):
        parts = [self.disjunction()]
        while True:
            if self.peek()[0] == "AND":
                self.take()
                parts.append(self.disjunction())
            elif self.starts_term():
                parts.append(self.disjunction())
            else:
                break
        return parts[0] if len(parts) == 1 else ("and", parts)

    def disjunction(self):
        parts = [self.negation()]
        while self.peek()[0] == "OR":
            self.take()
            parts.append(self.negation())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def negation(self):
        if self.peek()[0] in ("NOT", "NEG"):
            self.take()
            return ("not", self.negation())
        return self.primary()

    def primary(self):
        token = self.peek()
        if token[0] == "(":
            self.take()
            node = self.expression()
            self.take(")")
            return node
        if token[0] == "STR":
            self.take()
            if self.peek()[0] == "OP":
                raise FilterError("quoted field names are not modeled")
            return ("bare", token[1])
        if token[0] == "WORD":
            self.take()
            if self.peek()[0] == "(":
                self.take()
                args = []
                while self.peek()[0] != ")":
                    arg = self.take()
                    if arg[0] not in ("STR", "WORD"):
                        raise FilterError("unsupported function argument")
                    args.append(arg[1])
                    if self.peek()[0] == "WORD" and self.peek()[1] == ",":
                        self.take()
                self.take(")")
                if self.peek()[0] == "OP":
                    raise FilterError("function comparisons are not modeled")
                return ("func", token[1].lower(), args)
            if self.peek()[0] == "OP":
                op = self.take()[1]
                return ("cmp", token[2], op, self.value())
            return ("bare", token[1])
        raise FilterError(f"unexpected token {token[0]}")

    # Values: a literal or a parenthesized boolean group of literals.
    def value(self):
        token = self.peek()
        if token[0] == "(":
            self.take()
            node = self.value_expression()
            self.take(")")
            return node
        if token[0] == "STR":
            self.take()
            return ("v", token[1], True)
        if token[0] == "WORD":
            self.take()
            return ("v", token[1], False)
        raise FilterError("comparison value missing")

    def value_expression(self):
        parts = [self.value_disjunction()]
        while self.peek()[0] == "AND" or self.peek()[0] in ("STR", "WORD", "(", "NOT", "NEG"):
            if self.peek()[0] == "AND":
                self.take()
            parts.append(self.value_disjunction())
        return parts[0] if len(parts) == 1 else ("vand", parts)

    def value_disjunction(self):
        parts = [self.value_negation()]
        while self.peek()[0] == "OR":
            self.take()
            parts.append(self.value_negation())
        return parts[0] if len(parts) == 1 else ("vor", parts)

    def value_negation(self):
        if self.peek()[0] in ("NOT", "NEG"):
            self.take()
            return ("vnot", self.value_negation())
        return self.value()


def parse(text):
    if not isinstance(text, str) or not text.strip():
        raise FilterError("empty filter")
    parser = _Parser(tokenize(text))
    node = parser.expression()
    if parser.peek()[0] != "EOF":
        raise FilterError("trailing tokens")
    return node


# --- Three-valued evaluation ------------------------------------------------------------------------------------

def _and(values):
    values = list(values)
    if any(v is False for v in values):
        return False
    return None if any(v is None for v in values) else True


def _or(values):
    values = list(values)
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def _not(value):
    return None if value is None else not value


def _camel(segment):
    head, *rest = segment.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _flatten(values):
    out = []
    for value in values:
        if isinstance(value, list):
            out.extend(_flatten(value))
        else:
            out.append(value)
    return out


def lookup(event, segments):
    current = [event]
    for segment in segments:
        following = []
        for node in _flatten(current):
            if isinstance(node, dict):
                if segment in node:
                    following.append(node[segment])
                elif _camel(segment) in node:
                    following.append(node[_camel(segment)])
        if not following:
            return MISSING
        current = following
    return _flatten(current)


def _leaves(value):
    if isinstance(value, dict):
        return [x for v in value.values() for x in _leaves(v)]
    if isinstance(value, list):
        return [x for v in value for x in _leaves(v)]
    return [value]


def _scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _compare(op, leaf, literal, quoted, field):
    if isinstance(leaf, (dict, list)):
        return None
    text = _scalar(leaf)
    if op == "=":
        if text == literal:
            return True
        return None if text.casefold() == literal.casefold() else False
    if op == ":":
        if literal == "*" and not quoted:
            return True
        return literal.casefold() in text.casefold()
    if op == "=~":
        try:
            return re.search(literal, text) is not None
        except re.error:
            return None
    if op in (">", "<", ">=", "<="):
        if field and field[-1] == "severity" and text.upper() in SEVERITY and literal.upper() in SEVERITY:
            left, right = SEVERITY[text.upper()], SEVERITY[literal.upper()]
        else:
            try:
                left, right = float(text), float(literal)
            except ValueError:
                return None
        return {">": left > right, "<": left < right, ">=": left >= right, "<=": left <= right}[op]
    return None


def _value(node, leaves, op, field):
    kind = node[0]
    if kind == "vand":
        return _and(_value(x, leaves, op, field) for x in node[1])
    if kind == "vor":
        return _or(_value(x, leaves, op, field) for x in node[1])
    if kind == "vnot":
        return _not(_value(node[1], leaves, op, field))
    literal, quoted = node[1], node[2]
    if op in ("!=", "!~"):
        if len(leaves) != 1:
            return None  # negated comparisons over repeated fields are not modeled
        return _not(_compare("=" if op == "!=" else "=~", leaves[0], literal, quoted, field))
    return _or(_compare(op, leaf, literal, quoted, field) for leaf in leaves)


def evaluate(node, event):
    kind = node[0]
    if kind == "and":
        return _and(evaluate(x, event) for x in node[1])
    if kind == "or":
        return _or(evaluate(x, event) for x in node[1])
    if kind == "not":
        return _not(evaluate(node[1], event))
    if kind == "bare":
        needle = node[1].casefold()
        found = any(isinstance(x, str) and needle in x.casefold() for x in _leaves(event))
        return True if found else None
    if kind == "func":
        name, args = node[1], node[2]
        if name == "log_id" and len(args) == 1:
            log_name = event.get("logName")
            if not isinstance(log_name, str):
                return None
            return log_name.endswith("/logs/" + quote(args[0], safe=""))
        return None
    _, field, op, value = node
    leaves = lookup(event, field)
    if leaves is MISSING or not leaves:
        if field and field[0] in ABSENT_ROOTS and op not in ("!=", "!~"):
            return False  # the restriction cannot match an entry that lacks the payload member
        return None
    if op == ":" and value == ("v", "*", False):
        return True  # presence test; the field (possibly a message or repeated field) exists
    return _value(value, leaves, op, field)


def verdict(text, events):
    """'full' when the filter provably matches every event, 'none' when it provably matches none,
    otherwise 'partial' (some events, undecidable or unparsable)."""
    try:
        tree = parse(text)
    except (FilterError, RecursionError):
        return "partial", ["unparsable"]
    outcomes = [evaluate(tree, event) for event in events]
    if all(v is True for v in outcomes):
        return "full", outcomes
    if all(v is False for v in outcomes):
        return "none", outcomes
    return "partial", outcomes


def audit_event(project, service, method, resource_type, **payload):
    """Minimal Admin Activity audit entry for ``method``; only modeled fields are present."""
    return {
        "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": resource_type, "labels": {"project_id": project}},
        "severity": "NOTICE",
        "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": service,
                         "methodName": method, "authenticationInfo": {"principalEmail": "admin@example.com"}, **payload},
    }
