"""Unregistered proposal: URL metadata visible in explicitly selected projects.

No import-time registry mutation. This does not prove a hidden project universe.
"""
from . import result,unknown
from .facts import Unavailable,get,complete_items

CHECK='azure.review.devops.visible_clone_urls_without_userinfo'
DECLARATION={'id':CHECK,'provider':'azure','kind':'devops_project','target':'scope','category':'identity','finding_type':'secrets','severity':'high','dependencies':['devops_project'],'requirements':[],
 'title':'Visible selected Azure DevOps clone URLs do not contain userinfo',
 'description':'Reviews clone URL metadata returned by the read-only API for explicitly selected projects. Hidden repositories and other projects are outside this result.',
 'remediation':'Remove userinfo from the reported clone URL and rotate any exposed credential. Review inaccessible repositories separately.'}


def evaluate(item,index):
    try:
        from peaso.azure_devops_git_policy import evaluate_project
        context=get(index,'context',dict);scope=get(context,'scope',str)
        if get(context,'provider',str)!='azure':raise Unavailable('foreign provider')
        projects=complete_items(index,'devops_project')
        if not projects:return 'NOT_APPLICABLE',{'reason':'No visible project metadata was collected; no hidden repository claim.'}
        ids=[get(p,'id',str)for p in projects];metadata=get(context,'metadata',dict)
        common=get(projects[0],'_provenance',dict);visible=0;unresolved=False
        for project in projects:
            proof=get(project,'_provenance',dict)
            if (any(proof.get(k)!=common.get(k)for k in('organization','capture_id'))
                    or any(not isinstance(metadata.get(k),str)or proof.get(k)!=metadata[k]for k in('credential_context_id','customer_context_id'))):
                raise Unavailable('native selected-project capture mismatch')
            # Reuse the strict native schema, per-project identity and actual
            # paged HTTP receipts. Its hidden-universe limitation is preserved.
            finding=evaluate_project(project,scope,ids)
            if finding is True:return result(True,semantics='Userinfo observed in visible clone URL metadata; values redacted.')
            for repo in project['repositories']:
                facts=get(repo,'url_assessments',dict);visible+=1
                if facts.get('fields_complete')is not True or any(x.get('valid_parse')is not True for x in facts.get('items',[])):
                    unresolved=True
        if unresolved:raise Unavailable('Visible clone URL metadata missing or unparseable')
        if not visible:return 'NOT_APPLICABLE',{'reason':'No accessible repository URL metadata returned; hidden repositories remain unassessed.'}
        return result(False,visible_repository_count=visible,semantics='Only API-visible clone URL metadata in explicitly selected projects; hidden repositories and credential validity unassessed.')
    except Unavailable as exc:return unknown(str(exc))
