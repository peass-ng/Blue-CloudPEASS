"""Whitespace cannot establish a production change actor identity."""
import pytest
from peaso.checks import evaluate_check
from tests.test_peaso_azure_wave_change_native_integration import _case,SCOPE
CID='azure_c5_dev_08_02b'
@pytest.mark.parametrize('actor',[' ','\t','\n'])
def test_blank_actor_does_not_become_attributed_by_equal_blank_caller(actor):
    index=_case(CID)
    index['collections']['production_change'][0]['items'][0]['actorId']=actor
    index['collections']['activity_log'][0]['items'][0]['caller']=actor
    result,evidence=evaluate_check(CID,{'scope':SCOPE},index)
    assert result=='FAIL',evidence
