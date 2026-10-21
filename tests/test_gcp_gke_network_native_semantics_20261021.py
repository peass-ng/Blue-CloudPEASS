"""Offline exact evaluator bodies; normal release import remains epoch-gated."""
import ast
from pathlib import Path
import re
import sys

import pytest

from peaso.checks.claude_gcp_k8s_iam import gke_default_network
from peaso.checks.facts import Unavailable

@pytest.mark.parametrize('item,before,after',[
    ({'network':'prod-vpc','networkConfig':{'network':'projects/p/global/networks/default'}},'PASS','UNKNOWN'),
    ({'network':'default','networkConfig':{'network':'projects/p/global/networks/default'}},'FAIL','FAIL'),
    ({'network':'prod-vpc','networkConfig':{'network':'projects/p/global/networks/prod-vpc'}},'PASS','PASS'),
    ({'networkConfig':{'network':'projects/p/global/networks/default'}},'UNKNOWN','FAIL'),
    ({'network':'prod-vpc','networkConfig':{'network':'bad/path'}},'PASS','UNKNOWN'),
    ({'network':'projects/p/global/networks/default','networkConfig':{'network':'projects/foreign/global/networks/default'}},'PASS','UNKNOWN'),
    ({'network':''},'PASS','FAIL'),
])
def test_gke_native_network_forms(item,before,after):
    def status(fn):
        try: return fn(item, {})[0]
        except Unavailable: return 'UNKNOWN'
    assert status(gke_default_network)==after
    try:
        actual, evidence = gke_default_network(item, {})
    except Unavailable:
        return
    if actual in ('PASS', 'FAIL'):
        assert isinstance(evidence['network'], str)
