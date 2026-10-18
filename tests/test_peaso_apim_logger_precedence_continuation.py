"""Unknown logger usability cannot erase another API's measured failure."""
import copy
import pytest
from tests.test_peaso_apim_evidence_continuation import fixture,sw,_evaluate,children,SERVICE

@pytest.mark.parametrize('missing_first',[True,False])
def test_independent_missing_diagnostic_beats_unknown_logger_type(missing_first):
    parent,evidence=fixture(sw.DIAGNOSTICS)
    uncertain=evidence['apis']['items'][0]
    evidence['loggers']['items'][0]['properties']['loggerType']='unrecognized'
    missing=copy.deepcopy(uncertain)
    missing['id']=SERVICE+'/apis/missing-trace'
    missing['diagnostics']=children([])
    evidence['apis']=children([missing,uncertain] if missing_first else [uncertain,missing])
    assert _evaluate(parent,evidence)[0]=='FAIL'
