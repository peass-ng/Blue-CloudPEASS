"""Native Authorization List identity/source validation for reviewed IAM reads."""
import re
from urllib.parse import parse_qs,urlsplit

ARM='https://management.azure.com'
GUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'

def _scope(value):
    if (not isinstance(value,str) or not value or any(ord(c)<33 or ord(c)==127 for c in value)
            or any(c in value for c in ('?','#','%','\\')) or any(p in ('.','..') for p in value.split('/'))):
        raise ValueError('native authorization scope malformed')
    if value=='/' or re.fullmatch(r'/providers/Microsoft\.Management/managementGroups/[^/\s]+',value,re.I):return value
    if re.fullmatch(r'/subscriptions/'+GUID+r'(?:/resourceGroups/[^/\s]+(?:/providers/[^/\s]+(?:/[^/\s]+/[^/\s]+)+)?|/providers/[^/\s]+(?:/[^/\s]+/[^/\s]+)+)?',value,re.I):return value
    raise ValueError('native authorization scope unsupported')


def _assignable_scope(value):
    """Built-in roles can target Azure provider roots outside subscriptions."""
    try:
        return _scope(value)
    except ValueError:
        if (isinstance(value, str) and re.fullmatch(
                r'/providers/Microsoft\.[A-Za-z][A-Za-z0-9.]*(?:/[A-Za-z0-9._-]+)*', value, re.I)
                and not any(part in ('.', '..') for part in value.split('/'))):
            return value
        raise


def authorization_pages(reader,request,url,kind,requested_scope):
    endpoint={'role_assignment':'roleAssignments','role_definition':'roleDefinitions'}[kind]
    expected=requested_scope.rstrip('/')+'/providers/Microsoft.Authorization/'+endpoint
    initial=parse_qs(urlsplit(url).query)
    def source(page_url,*,body=None,audience=ARM):
        parsed=urlsplit(page_url);query=parse_qs(parsed.query)
        if (body is not None or audience!=ARM or parsed.scheme!='https' or parsed.netloc!='management.azure.com'
                or parsed.path!=expected or parsed.fragment or query.get('api-version')!=['2022-04-01']
                or query.get('$filter')!=initial.get('$filter')):
            raise ValueError('Authorization List source changed')
        return request(page_url,body=body,audience=audience)
    seen=set()
    for page in reader.pages(source,url):
        projected=[]
        for row in page:
            if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not isinstance(row.get('properties'),dict):
                raise ValueError('native authorization row unavailable')
            match=re.fullmatch(r'(.*)/providers/Microsoft\.Authorization/'+endpoint+r'/([^/?#%\s\\]+)',row['id'],re.I)
            if not match or str(row.get('type','')).casefold()!=('Microsoft.Authorization/'+endpoint).casefold():
                raise ValueError('native authorization type or identity inconsistent')
            if not re.fullmatch(GUID,match[2],re.I):raise ValueError('native authorization ID is not a GUID')
            if not isinstance(row.get('name'),str) or row['name'].casefold()!=match[2].casefold():
                raise ValueError('native authorization name differs from resource ID')
            parent=_scope(match[1] or '/')
            if row['id'].casefold() in seen:raise ValueError('duplicate native authorization identity')
            seen.add(row['id'].casefold())
            props=row['properties']
            if kind=='role_assignment':
                principal=props.get('principalId');role=props.get('roleDefinitionId')
                reference=re.fullmatch(r'(.*)/providers/Microsoft\.Authorization/roleDefinitions/('+GUID+')',role,re.I) if isinstance(role,str) else None
                if (not isinstance(principal,str) or not re.fullmatch(GUID,principal,re.I)
                        or principal.replace('-','')=='0'*32 or reference is None):
                    raise ValueError('native assignment principal or role reference malformed')
                _scope(reference[1] or '/')
                declared=_scope(props.get('scope'))
                if parent.casefold()!=declared.casefold():raise ValueError('assignment ID parent differs from declared scope')
                if requested_scope=='/':
                    if declared!='/':raise ValueError('root atScope List returned non-root assignment')
                elif declared.casefold().startswith('/subscriptions/') and not (declared.casefold()==requested_scope.casefold() or declared.casefold().startswith(requested_scope.casefold()+'/')):
                    raise ValueError('foreign subscription assignment from scoped List')
                # Coherent root/MG rows returned by this scoped native List are
                # inherited applicability evidence, not an arbitrary ID prefix.
            else:
                scopes=props.get('assignableScopes')
                if not isinstance(scopes,list) or not scopes:raise ValueError('role assignability unavailable')
                scopes=[_assignable_scope(s) for s in scopes]
                if requested_scope!='/':
                    applicable=any(s=='/' or s.casefold().startswith('/providers/microsoft.management/managementgroups/') or
                        s.casefold()==requested_scope.casefold() or s.casefold().startswith(requested_scope.casefold()+'/') or requested_scope.casefold().startswith(s.casefold()+'/') for s in scopes)
                    if not applicable:raise ValueError('role definition not applicable to requested scope')
            if '_authorization_native_list' in row:raise ValueError('conflicting authorization source marker')
            projected.append({**row,'_authorization_native_list':{'source_operation':endpoint+'_ListForScope','api_version':'2022-04-01',
                'read_only':True,'requested_scope':requested_scope,'request_path':expected,'filter':initial.get('$filter',[None])[0]}})
        yield projected


def graph_identity(kind,row):
    if kind=='named_location':
        if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not re.fullmatch(GUID,row['id'],re.I):
            raise ValueError('native named location identity malformed')
    elif kind=='authentication_methods_policy':
        if not isinstance(row,dict) or row.get('id')!='authenticationMethodsPolicy':
            raise ValueError('native authentication methods policy singleton identity malformed')
    return row
