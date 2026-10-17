"""Legacy account scan must reuse existing analyzers without paid mutations."""

import ast
from pathlib import Path

from botocore.exceptions import ClientError


SOURCE = Path(__file__).resolve().parents[1] / "Blue-AWSPEAS.py"


def _legacy_lookup():
    tree = ast.parse(SOURCE.read_text())
    process = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "process_account")
    lookups = [
        node for node in ast.walk(process)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Tuple)
        and [name.id for name in node.target.elts if isinstance(name, ast.Name)] == ["analyzer_type", "error_operation"]
    ]
    assert len(lookups) == 1
    module = ast.fix_missing_locations(ast.Module(body=[lookups[0]], type_ignores=[]))
    return tree, compile(module, str(SOURCE), "exec")


def test_legacy_scan_never_creates_or_deletes_analyzers():
    tree, _ = _legacy_lookup()
    writes = {"create_analyzer", "delete_analyzer"}
    assert not [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in writes
    ]


def test_legacy_scan_reuses_existing_analyzers_and_keeps_absence_honest():
    _, lookup = _legacy_lookup()

    class FakeAnalyzer:
        def __init__(self, answers):
            self.answers = answers
            self.calls = []

        def list_analyzers(self, *, type):
            self.calls.append(("list_analyzers", type))
            answer = self.answers[type]
            if isinstance(answer, Exception):
                raise answer
            return {"analyzers": answer}

        def create_analyzer(self, **kwargs):
            raise AssertionError("paid analyzer creation forbidden")

        def delete_analyzer(self, **kwargs):
            raise AssertionError("analyzer deletion forbidden")

    for unused, external, expected in (
        ([{"arn": "existing-unused"}], [{"arn": "existing-external"}], ("existing-unused", "existing-external", 0)),
        ([], [], (None, None, 0)),
        (ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListAnalyzers"), [], (None, None, 1)),
    ):
        client = FakeAnalyzer({"ACCOUNT_UNUSED_ACCESS": unused, "ACCOUNT": external})
        scope = {
            "accessanalyzer": client, "analyzer_arn": None, "analyzer_arn_exposed": None,
            "permission_errors": [], "ClientError": ClientError, "verbose": False,
        }
        exec(lookup, scope)
        assert (scope["analyzer_arn"], scope["analyzer_arn_exposed"], len(scope["permission_errors"])) == expected
        assert client.calls == [("list_analyzers", "ACCOUNT_UNUSED_ACCESS"), ("list_analyzers", "ACCOUNT")]
