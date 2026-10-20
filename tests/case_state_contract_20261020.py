"""Preserve opaque admission owners while independently recording mutable state."""
from copy import deepcopy
from tests.aws_k8s_current_native_inputs_20261020 import case_state


def case_copy(value):
    from peaso import azure_function_package_index_20261020 as owner
    memo = {}
    def visit(member):
        if type(member) in (owner._Admitted, owner._Assertions):
            memo[id(member)] = member
        elif isinstance(member, dict):
            for item in member.values():
                visit(item)
        elif isinstance(member, (list, tuple)):
            for item in member:
                visit(item)
    visit(value)
    return deepcopy(value, memo)
