"""Exact candidate evaluator bodies with the normal release helper contracts."""
import ast
import os
from pathlib import Path
import re
import sys

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude_gcp_k8s_common as common
from peaso.checks.claude_gcp_k8s_compute import firewall_default_rules

def test_default_named_rule_on_custom_network_is_not_default_rule():
    after = firewall_default_rules
    index = common.scope_index({}, 'projects/p')
    rule = common.fw(['0.0.0.0/0'], [{'IPProtocol': 'tcp', 'ports': ['22']}],
                     name='default-allow-ssh', network='projects/p/global/networks/custom')
    assert after(rule, index)[0] == 'NOT_APPLICABLE'
    rule['network'] = 'https://www.googleapis.com/compute/v1/projects/p/global/networks/default'
    assert after(rule, index)[0] == 'FAIL'
    rule['network'] = 'projects/foreign/global/networks/default'
    with pytest.raises(common.Unavailable):
        after(rule, index)
    rule['network'] = 'global/networks/default'
    with pytest.raises(common.Unavailable):
        after(rule, index)
    del rule['network']
    with pytest.raises(common.Unavailable):
        after(rule, index)
    rule['network'] = 'projects/p/global/networks/default'
    rule['disabled'] = True
    assert after(rule, index)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('suffix', ['gmail.com', 'googlegroups.com'])
def test_documented_bigquery_domain_grant_cannot_pass_as_clean(suffix):
    cid = 'gcp.claude.bigquery_dataset.' + ('no_gmail_access' if suffix == 'gmail.com' else 'no_googlegroups_access')
    after = next(check for check in CHECKS if check.id == cid).evaluate
    index = common.scope_index({}, 'projects/p')
    grant = {'access': [{'role': 'READER', 'domain': suffix}]}
    assert after(grant, index)[0] == 'FAIL'
    assert after({'access': [{'role': 'READER', 'domain': 'example.com'}]}, index)[0] == 'PASS'
    assert after({'access': [{'role': 'READER', 'userByEmail': 'a@' + suffix}]}, index)[0] == 'FAIL'
    assert after({'access': [{'role': 'READER', 'domain': suffix,
                              'userByEmail': 'a@example.com'}]}, index)[0] == 'UNKNOWN'
    assert after({'access': [{'role': 'READER', 'domain': 'bad..domain'}]}, index)[0] == 'UNKNOWN'
