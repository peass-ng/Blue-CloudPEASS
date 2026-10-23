"""A hoisted guard must remain a proven leading rejection in its validator."""
import ast
from copy import deepcopy
import inspect
import json
from pathlib import Path
import textwrap

from peaso.attack_detection import rules


def source_guard(node):
    if (isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or)
            and isinstance(node.values[0], ast.UnaryOp) and isinstance(node.values[0].op, ast.Not)
            and isinstance(node.values[0].operand, ast.Name) and node.values[0].operand.id == 'plain_source'):
        return node.values[1]
    return node


def test_every_hoisted_guard_matches_a_leading_authoritative_rejection():
    tree = ast.parse(inspect.getsource(rules.detect_aws_events))
    guarded = [node for node in ast.walk(tree)
               if isinstance(node, ast.IfExp) and isinstance(node.body, ast.Call)
               and isinstance(source_guard(node.test), ast.Compare) and isinstance(source_guard(node.test).left, ast.Name)
               and source_guard(node.test).left.id == 'event_source'
               and isinstance(node.body.func, ast.Name)
               and node.body.func.id.startswith('normalize')]
    assert guarded
    for node in guarded:
        conditional = source_guard(node.test)
        fn = getattr(rules, node.body.func.id)
        body = ast.parse(textwrap.dedent(inspect.getsource(fn))).body[0]
        statements = [stmt for stmt in body.body if not (
            isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str))]
        guard = statements[0]
        assert isinstance(guard, ast.If)
        assert len(guard.body) == 1 and isinstance(guard.body[0], ast.Return)
        assert guard.body[0].value is None or ast.literal_eval(guard.body[0].value) is None
        rejection = guard.test.values[0] if isinstance(guard.test, ast.BoolOp) else guard.test
        if isinstance(guard.test, ast.BoolOp):
            assert isinstance(guard.test.op, ast.Or)
        assert isinstance(rejection, ast.Compare) and len(rejection.ops) == 1
        assert ast.unparse(rejection.left) == f"{body.args.args[0].arg}.get('eventSource')"
        assert isinstance(conditional.left, ast.Name) and conditional.left.id == 'event_source'
        expected = ast.literal_eval(rejection.comparators[0])
        actual = ast.literal_eval(conditional.comparators[0])
        if isinstance(rejection.ops[0], ast.NotEq):
            assert isinstance(conditional.ops[0], ast.Eq) and actual == expected
        else:
            assert isinstance(rejection.ops[0], ast.NotIn)
            assert isinstance(conditional.ops[0], ast.In) and set(actual) == set(expected)


def test_full_normalized_outputs_match_unhoisted_path_for_fixture_events(monkeypatch):
    tree = ast.parse(inspect.getsource(rules.detect_aws_events))

    def unhoist(node):
        if (isinstance(node, ast.IfExp) and isinstance(source_guard(node.test), ast.Compare)
                and isinstance(source_guard(node.test).left, ast.Name) and source_guard(node.test).left.id == 'event_source'):
            return node.body
        return node

    # The original emitter has a long concatenation expression; avoid a
    # recursive AST deepcopy/visitor on that expression.
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if isinstance(value, ast.AST):
                setattr(parent, field, unhoist(value))
            elif isinstance(value, list):
                setattr(parent, field, [unhoist(item) for item in value])
    baseline_tree = ast.fix_missing_locations(tree)
    namespace = dict(vars(rules))
    exec(compile(baseline_tree, '<audit-dispatch-reference>', 'exec'), namespace)
    baseline = namespace['detect_aws_events']
    records = []

    def collect(value):
        if isinstance(value, dict):
            if 'eventSource' in value:
                records.append(value)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    for path in sorted((Path(__file__).parent / 'fixtures').glob('*events.json')):
        collect(json.loads(path.read_text()))
    records.extend({'eventSource': source, 'eventName': name} for source in
                   (None, '', 'example.invalid', 1) for name in (None, '', 'Unknown'))
    assert len(records) > 100
    outputs = []

    def observe(records, selected, normalizer, product):
        outputs.append([normalizer(record) for record in records])
        return []

    monkeypatch.setattr(rules, '_detect_events', observe)
    namespace['_detect_events'] = observe
    rules.detect_aws_events(deepcopy(records), [])
    actual = outputs[:]
    outputs.clear()
    baseline(deepcopy(records), [])
    assert outputs == actual
