"""Consistent coverage for defaults already derived from a complete Lambda read."""


def normalize_documented_omissions(item):
    configuration = item.get("Configuration")
    if not isinstance(configuration, dict) or configuration.get("collection_status") != "collected":
        return item

    def normalize(parent, field, expected):
        coverage = parent.get("_coverage", {})
        if not isinstance(coverage, dict):
            return
        proof = coverage.get(field)
        if (isinstance(proof, dict) and proof.get("status") == "empty"
                and proof.get("reason") == "documented_optional_api_omission"
                and proof.get("source_operation") == "lambda:GetFunctionConfiguration"
                and field in parent and parent[field] == expected):
            # This is a derived, known default value. Empty coverage means no
            # retained fact and would contradict the deliberately stored value.
            proof["status"] = "collected"

    normalize(item, "DeadLetterConfig", {})
    normalize(item, "VpcConfig", {"VpcId": ""})
    vpc = item.get("VpcConfig")
    if isinstance(vpc, dict):
        normalize(vpc, "VpcId", "")
    return item
