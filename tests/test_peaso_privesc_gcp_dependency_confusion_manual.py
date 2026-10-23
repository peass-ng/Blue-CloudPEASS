"""Dependency confusion requires manual consumer and package evidence."""

import json
from pathlib import Path

from peaso import privesc
from peaso.privesc.gcp_observed_impact import IMPACT


def test_artifact_supply_chain_manual_paths_do_not_emit_iam_only_edges_or_ui_copy():
    manual_ids = {
        "gcp-artifactregistry-repositories-update-dependency-confusion",
        "gcp-artifactregistry-tags-update",
    }
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    explanation = json.loads((Path(__file__).resolve().parents[1] /
                              "peaso/privesc/finding_explanation.json").read_text())
    for ident in manual_ids:
        assert ident not in active
        assert ident not in IMPACT
        assert ident not in explanation
