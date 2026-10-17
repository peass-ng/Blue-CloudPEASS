"""Native account-scoped Budgets action configuration, without executing actions."""
import copy,re
from peaso.aws_budget_policy import STATUSES,definition,execution

KIND='budget_action'
SPECS={KIND:('budgets','describe_budget_actions_for_account','Actions')}
GLOBAL_TYPES={KIND}
NATIVE_IDS={KIND:'ActionId'}
READ_ACTIONS={('budgets','describe_budget_action')}


def collect(requests,session,region,account):
    from .aws import ReadResult,ReadFailure
    def require(value):
        if not isinstance(value,dict)or value.get('collection_status')!='collected':
            raise ReadFailure(value.get('collection_status','malformed')if isinstance(value,dict)else'malformed',(value.get('error')or{}).get('code','native_budget_detail_incomplete')if isinstance(value,dict)else'native_budget_detail_incomplete')
        return value
    try:
        identity=require(requests.detail(session,'sts',region,'get_caller_identity'))
        m=re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):(?:sts|iam)::'+re.escape(account)+r':.+',identity.get('Arn',''))
        if identity.get('Account')!=account or not m:raise ValueError('budget caller identity mismatch')
        partition=m.group(1)
        listing=requests.pages(session,'budgets',region,'describe_budget_actions_for_account','Actions',AccountId=account)
        if listing.status not in('collected','empty'):raise ReadFailure(listing.status,(listing.error or{}).get('code','native_budget_actions_incomplete'))
        seen=set();out=[]
        for row in listing.items:
            aid=row.get('ActionId');name=row.get('BudgetName')
            if not isinstance(aid,str)or not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',aid)or aid in seen:raise ValueError('budget action UUID missing or duplicate')
            seen.add(aid)
            if not isinstance(name,str)or not 1<=len(name)<=100 or any(c in name for c in(':','\\'))or '/action/'in name or any(ord(c)<32 for c in name):raise ValueError('invalid native budget name')
            raw=require(requests.detail(session,'budgets',region,'describe_budget_action',AccountId=account,BudgetName=name,ActionId=aid))
            action=raw.get('Action')
            if raw.get('AccountId')!=account or raw.get('BudgetName')!=name or not isinstance(action,dict)or action.get('ActionId')!=aid or action.get('BudgetName')!=name:raise ValueError('budget action account/identity join mismatch')
            fields=('ActionId','BudgetName','ActionType','Status','ActionThreshold','ExecutionRoleArn','ApprovalModel','NotificationType','Definition')
            if any(row.get(k)!=action.get(k)for k in fields):raise ValueError('budget action LIST/GET configuration changed')
            if action.get('Status')not in STATUSES or action.get('ActionType')not in {'RUN_SSM_DOCUMENTS','APPLY_IAM_POLICY','APPLY_SCP_POLICY'}:raise ValueError('native budget action state/type unsupported')
            execution(action,account,partition)
            projected={k:copy.deepcopy(action[k])for k in fields}
            if action['ActionType']=='RUN_SSM_DOCUMENTS':
                value=action.get('Definition')
                if not isinstance(value,dict)or set(value)!={'SsmActionDefinition'}or not isinstance(value['SsmActionDefinition'],dict)or set(value['SsmActionDefinition'])!={'ActionSubType','Region','InstanceIds'}:raise ValueError('native SSM stop definition unsupported')
                native=definition({**value['SsmActionDefinition'],**{k:action[k]for k in('ExecutionRoleArn','ApprovalModel','NotificationType','ActionThreshold')}},account,partition)
                if session.get_partition_for_region(native['Region'])!=partition:raise ValueError('budget target Region partition mismatch')
            else:
                # Irrelevant IAM/SCP policy details and subscriber addresses are
                # not required to determine whether this is an SSM stop action.
                projected['Definition']={}
            projected.update(AccountId=account,_provenance={'native_budget_action_schema':1,'read_only':True,'detail_get_complete':True,'source_operations':['budgets:DescribeBudgetActionsForAccount','budgets:DescribeBudgetAction'],'partition':partition,'execution_observed':False})
            out.append(projected)
        return ReadResult(out,'collected'if out else'empty')
    except ReadFailure as exc:return ReadResult([],exc.status,{'code':exc.code})
    except (ValueError,TypeError,KeyError,AttributeError):return ReadResult([],'malformed',{'code':'native_budget_action_join_unresolved'})

FETCHERS={KIND:collect}
