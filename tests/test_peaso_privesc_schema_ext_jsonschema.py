"""The published JSON Schema (privesc-technique.schema.json) matches schema.py and accepts every catalog file."""
from __future__ import annotations

import copy
import json
import re

import pytest
import yaml

from peaso.privesc.schema import JSON_SCHEMA_FILE, catalog_files, json_schema, load_catalog, validate_entry, validate_excluded

try:  # jsonschema is optional: CI installs only PyYAML + pytest, so never skip - fall back to MiniValidator.
    import jsonschema
except ImportError:  # pragma: no cover - exercised where jsonschema is absent
    jsonschema = None


class MiniError:
    def __init__(self, path, message):
        self.json_path, self.message = path, message


class MiniValidator:
    """Draft 2020-12 subset covering every keyword the generated schema uses; an unsupported keyword is a hard
    failure (so a generator change cannot make this fallback silently weaker)."""
    ANNOTATIONS = {"$schema", "$id", "title", "description", "$defs"}
    KEYWORDS = {"$ref", "type", "enum", "const", "properties", "additionalProperties", "required", "items", "minItems",
                "minLength", "minProperties", "pattern", "propertyNames", "dependentRequired", "allOf", "anyOf", "oneOf",
                "not", "if", "then"}
    TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}

    def __init__(self, schema):
        self.root = schema
        self._check(schema)

    def _check(self, node):
        if isinstance(node, dict):
            unknown = set(node) - self.ANNOTATIONS - self.KEYWORDS
            assert not unknown, f"MiniValidator does not implement {sorted(unknown)}"
            for key, value in node.items():
                if key in ("properties", "$defs"):
                    for sub in value.values():
                        self._check(sub)
                elif key in ("allOf", "anyOf", "oneOf"):
                    for sub in value:
                        self._check(sub)
                elif key in ("items", "additionalProperties", "propertyNames", "not", "if", "then") and isinstance(value, dict):
                    self._check(value)

    def _type_ok(self, value, wanted):
        for t in wanted if isinstance(wanted, list) else [wanted]:
            if t == "integer" and isinstance(value, int) and not isinstance(value, bool):
                return True
            if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
                return True
            if t in self.TYPES and isinstance(value, self.TYPES[t]) and (t == "boolean" or not isinstance(value, bool)):
                return True
        return False

    def iter_errors(self, instance, schema=None, path="$"):
        schema = self.root if schema is None else schema
        if schema is True:
            return
        if schema is False:
            yield MiniError(path, "false schema")
            return
        if "$ref" in schema:
            node = self.root
            for part in schema["$ref"].lstrip("#/").split("/"):
                node = node[part]
            yield from self.iter_errors(instance, node, path)
        if "type" in schema and not self._type_ok(instance, schema["type"]):
            yield MiniError(path, f"{instance!r} is not of type {schema['type']}")
            return
        if "enum" in schema and instance not in schema["enum"]:
            yield MiniError(path, f"{instance!r} not in enum")
        if "const" in schema and instance != schema["const"]:
            yield MiniError(path, f"{instance!r} != const {schema['const']!r}")
        if isinstance(instance, str):
            if len(instance) < schema.get("minLength", 0):
                yield MiniError(path, "too short")
            if "pattern" in schema and not re.search(schema["pattern"], instance):
                yield MiniError(path, f"{instance!r} does not match {schema['pattern']}")
        if isinstance(instance, list):
            if len(instance) < schema.get("minItems", 0):
                yield MiniError(path, "too few items")
            if isinstance(schema.get("items"), (dict, bool)):
                for i, item in enumerate(instance):
                    yield from self.iter_errors(item, schema["items"], f"{path}[{i}]")
        if isinstance(instance, dict):
            if len(instance) < schema.get("minProperties", 0):
                yield MiniError(path, "too few properties")
            for key in schema.get("required", []):
                if key not in instance:
                    yield MiniError(path, f"{key!r} is a required property")
            for key, needed in schema.get("dependentRequired", {}).items():
                if key in instance:
                    for other in needed:
                        if other not in instance:
                            yield MiniError(path, f"{other!r} is required by {key!r}")
            props = schema.get("properties", {})
            for key, value in instance.items():
                if "propertyNames" in schema:
                    yield from self.iter_errors(key, schema["propertyNames"], f"{path}.{key}(name)")
                if key in props:
                    yield from self.iter_errors(value, props[key], f"{path}.{key}")
                elif "additionalProperties" in schema:
                    yield from self.iter_errors(value, schema["additionalProperties"], f"{path}.{key}")
        for sub in schema.get("allOf", []):
            yield from self.iter_errors(instance, sub, path)
        if "anyOf" in schema and not any(self.valid(instance, sub) for sub in schema["anyOf"]):
            yield MiniError(path, "no anyOf branch matches")
        if "oneOf" in schema and sum(self.valid(instance, sub) for sub in schema["oneOf"]) != 1:
            yield MiniError(path, "not exactly one oneOf branch matches")
        if "not" in schema and self.valid(instance, schema["not"]):
            yield MiniError(path, "matches a 'not' schema")
        if "if" in schema and "then" in schema and self.valid(instance, schema["if"]):
            yield from self.iter_errors(instance, schema["then"], path)

    def valid(self, instance, schema):
        return next(iter(self.iter_errors(instance, schema)), None) is None


def _message(errors):
    if jsonschema is not None and not isinstance(errors[0], MiniError):
        return jsonschema.exceptions.best_match(errors).message[:400]
    return f"{errors[0].json_path}: {errors[0].message}"[:400]


@pytest.fixture(scope="module", params=["jsonschema", "mini"])
def validator(request):
    schema = json.loads(JSON_SCHEMA_FILE.read_text())
    if request.param == "mini":
        return MiniValidator(schema)
    if jsonschema is None:
        pytest.skip("jsonschema not installed; the MiniValidator parametrization runs these tests")
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_mini_validator_agrees_with_jsonschema_on_every_catalog_file_and_mutation():
    if jsonschema is None:
        pytest.skip("cross-check needs jsonschema")
    schema = json.loads(JSON_SCHEMA_FILE.read_text())
    mini, full = MiniValidator(schema), jsonschema.Draft202012Validator(schema)
    docs = [yaml.safe_load(p.read_text()) for p in catalog_files()] + [[BASE]] + [[bad] for _, bad in _mutations()]
    for doc in docs:
        assert mini.valid(doc, schema) == full.is_valid(doc)


def test_committed_json_schema_is_generated_from_the_registries():
    assert json.loads(JSON_SCHEMA_FILE.read_text()) == json.loads(json.dumps(json_schema())), \
        "regenerate with: python -m peaso.privesc.schema --write-json-schema"


def test_every_catalog_file_validates_against_json_schema_and_schema_py(validator):
    loaded = load_catalog()
    assert loaded["errors"] == []
    schema = json.loads(JSON_SCHEMA_FILE.read_text())
    active_schema = {"$defs": schema["$defs"], **schema["anyOf"][0]}
    active_validator = (MiniValidator(active_schema) if isinstance(validator, MiniValidator)
                        else validator.evolve(schema=active_schema))
    for path in catalog_files():
        data = yaml.safe_load(path.read_text())
        if path.name.startswith("_excluded"):
            # Exclusion ledgers can retain historical metadata that is not an
            # active technique. Their loader contract is source + reason.
            assert not validate_excluded(data, str(path))
            continue
        # An empty YAML document represents an empty active list to the loader.
        errors = sorted(active_validator.iter_errors([] if data is None else data), key=lambda e: e.json_path)
        assert not errors, f"{path.name}: {_message(errors)}"
    assert len(loaded["entries"]) > 0


BASE = {"id": "aws-t-json", "provider": "aws", "service": "t", "title": "t", "source": "src/x.md", "summary": "s",
        "severity": "high", "mitigation": "m",
        "requires": {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"},
                                {"any_of": [{"action": "lambda:InvokeFunction"},
                                            [{"action": "lambda:CreateFunctionUrlConfig", "bind": "fn"},
                                             {"action": "lambda:InvokeFunctionUrl", "bind": "fn"}]]}]},
        "target": {"kind": "aws_role", "selector": {"trust_allows_service": "lambda.amazonaws.com",
                                                    "exclude_target_id_glob": "*:role/aws-reserved/*"},
                   "scope": "same_account", "outcome": "workload_execution"}}


def _mutations():
    def m(fn):
        e = copy.deepcopy(BASE)
        fn(e)
        return e
    yield "unknown selector", m(lambda e: e["target"]["selector"].update(made_up=True))
    yield "kind of other provider", m(lambda e: e["target"].update(kind="gcp_service_account"))
    yield "group with two keys", m(lambda e: e["requires"]["all_of"].append({"all_of": [{"action": "a:B"}], "any_of": [{"action": "a:C"}]}))
    yield "wildcard action", m(lambda e: e["requires"]["all_of"].append({"action": "iam:*"}))
    yield "unknown outcome", m(lambda e: e["target"].update(outcome="become"))
    yield "bad request_context", m(lambda e: e["requires"]["all_of"].append({"action": "a:B", "request_context": {"a:b": 3}}))
    yield "unknown entry field", m(lambda e: e.update(steps=["x"]))
    yield "gcp request_context", m(lambda e: e.update(id="gcp-t-json", provider="gcp", requires={"all_of": [
        {"permission": "iam.serviceAccounts.actAs", "request_context": {"a:b": "c"}}]},
        target={"kind": "gcp_service_account", "scope": "same_project"}))


def test_base_entry_is_valid_for_both(validator):
    assert not list(validator.iter_errors([BASE]))
    assert validate_entry(BASE, hacktricks_root="/nonexistent-hacktricks")[0] == []


@pytest.mark.parametrize("label,bad", list(_mutations()))
def test_invalid_entries_are_rejected_by_both(validator, label, bad):
    assert list(validator.iter_errors([bad])), label
    assert validate_entry(bad, hacktricks_root="/nonexistent-hacktricks")[0], label
