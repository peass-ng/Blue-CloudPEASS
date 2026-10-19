"""Unknown EFS automatic-backup metadata cannot establish a safe backup state."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

@pytest.mark.parametrize('cid',['aws.c2b.efs.backup_not_disabled','aws.c2b.efs.automatic_backups_enabled'])
@pytest.mark.parametrize('value',['garbage','','enabled',' DISABLED'])
def test_unrecognized_backup_status_is_unknown(cid,value):
    c=next(c for c in CHECKS if c.id==cid);item=deepcopy(CASES[cid]['pass'])
    item['BackupPolicy']['BackupPolicy']['Status']=value
    assert c.evaluate(item,{})[0]=='UNKNOWN'

@pytest.mark.parametrize('cid,values',[('aws.c2b.efs.backup_not_disabled',{'ENABLED':'PASS','ENABLING':'PASS','DISABLED':'FAIL','DISABLING':'FAIL'}),('aws.c2b.efs.automatic_backups_enabled',{'ENABLED':'PASS','ENABLING':'FAIL','DISABLED':'FAIL','DISABLING':'FAIL'})])
def test_recognized_native_transition_criteria_are_preserved(cid,values):
    c=next(c for c in CHECKS if c.id==cid)
    for value,status in values.items():
        item=deepcopy(CASES[cid]['pass']);item['BackupPolicy']['BackupPolicy']['Status']=value
        assert c.evaluate(item,{})[0]==status
