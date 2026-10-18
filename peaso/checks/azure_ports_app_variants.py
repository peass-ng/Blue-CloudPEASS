"""Exact App Service table/kind selectors and explicitly pinned runtime baselines."""
import re
from . import register,result
from .facts import get,list_of_objects,Unavailable
from .fixtures import CASES,nest
CHECK_IDS=[]
SOURCE_QUERIES={}


def applicable(item,selector):
    kind=get(item,'kind',str)
    web=kind!='functionapp';function='functionapp' in kind;tokens=kind.split(',')
    return {'web':web,'function':function,'api':web and any(t.endswith('api') for t in tokens),'api_exact':web and kind=='api','app':web and any(t.startswith('app') for t in tokens),'app_linux':web and any(t.startswith('app') for t in tokens) and 'linux' in tokens,'function_linux':function and any(t.startswith('functionapp') for t in tokens) and 'linux' in tokens,'function_prefix':function and any(t.startswith('functionapp') for t in tokens)}[selector]


SPECS={
'appservice_api_app_use_https':('api','properties.httpsOnly',True,False,bool),
'appservice_api_app_remote_debugging_disabled':('api_exact','configuration.properties.remoteDebuggingEnabled',False,True,bool),
'appservice_api_app_latest_tls_version':('api','configuration.properties.minTlsVersion','1.2','1.0',str),
'appservice_api_app_client_certificates_on':('api','properties.clientCertEnabled',True,False,bool),
'appservice_api_app_ftps_enabled':('api','configuration.properties.ftpsState','FtpsOnly','AllAllowed',str),
'appservice_function_app_client_certificates_on':('function','properties.clientCertEnabled',True,False,bool),
'appservice_function_app_remote_debugging_disabled':('function','configuration.properties.remoteDebuggingEnabled',False,True,bool),
'appservice_function_app_latest_tls_version':('function','configuration.properties.minTlsVersion','1.2','1.0',str),
'appservice_function_app_only_https_accessible':('function','properties.httpsOnly',True,False,bool),
'appservice_function_app_ftps_enabled':('function_prefix','configuration.properties.ftpsState','FtpsOnly','AllAllowed',str),
'appservice_function_app_latest_http_version':('function_linux','configuration.properties.http20Enabled',True,False,bool),
'appservice_web_app_client_certificates_on':('app','properties.clientCertEnabled',True,False,bool),
'appservice_web_app_ftps_enabled':('app','configuration.properties.ftpsState','FtpsOnly','AllAllowed',str),
'appservice_web_app_always_on':('web','configuration.properties.alwaysOn',True,False,bool),
'appservice_web_app_failed_request_tracing_enabled':('web','logsConfiguration.properties.failedRequestsTracing.enabled',True,False,bool),
'appservice_authentication_enabled':('web','authSettingsV1.properties.enabled',True,False,bool),
'appservice_function_app_authentication_on':('function','authSettingsV1.properties.enabled',True,False,bool),
}


def _port(query,kind='app_service',deps=None):
    cid='azure.port.'+query;CHECK_IDS.append(cid);SOURCE_QUERIES[query]=cid
    return register(cid,'azure','hardening',kind,'App Service declared baseline: '+query.removeprefix('appservice_').replace('_',' '),'medium','CM-6','Review declared configuration and service/SKU constraints; no requests, logs, deployment settings or authentication secrets are read or changed.',dependencies=deps or [kind])


def _scalar(query,spec):
    selector,path,good,bad,expected=spec
    @_port(query)
    def evaluate(item,index):
        if not applicable(item,selector):return 'NOT_APPLICABLE',{'reason':'Outside exact source table/kind selector'}
        value=get(item,path,expected)
        if path.endswith('minTlsVersion'):
            if value not in ('1.0','1.1','1.2','1.3'):raise Unavailable('Unknown TLS version')
            failed=value<'1.2'
        elif path.endswith('ftpsState'):
            if value not in ('AllAllowed','FtpsOnly','Disabled'):raise Unavailable('Unknown deployment FTP mode')
            failed=value=='AllAllowed'
        else:failed=value!=good
        return result(failed,field=path,configured=value,source_selector=selector,semantics='Explicit declaration, not effective enforcement; legacy V1 auth flag requires captured V1 metadata and is never inferred from V2')
    kind={'web':'app','app':'app','api':'api','api_exact':'api','function':'functionapp','function_prefix':'functionapp','function_linux':'functionapp,linux'}[selector]
    CASES[SOURCE_QUERIES[query]]={'pass':{'kind':kind,**nest(path,good)},'fail':{'kind':kind,**nest(path,bad)}}
for _q,_s in SPECS.items():_scalar(_q,_s)


for _query,_selector in [('appservice_api_app_cors_no_star','api'),('appservice_function_app_cors_no_star','function'),('appservice_web_app_cors_no_star','web')]:
    def _cors(query,selector):
        @_port(query)
        def evaluate(item,index):
            if not applicable(item,selector):return 'NOT_APPLICABLE',{'reason':'Outside exact source table/kind selector'}
            origins=get(item,'configuration.properties.cors.allowedOrigins',list)
            if any(not isinstance(v,str) for v in origins):raise Unavailable('Malformed CORS origins')
            return result('*' in origins,allowed_origins=origins,semantics='Literal wildcard only; browser CORS is not an authorization or network perimeter')
        kind='api' if selector=='api' else 'functionapp' if selector=='function' else 'app'
        CASES[SOURCE_QUERIES[query]]={'pass':{'kind':kind,**nest('configuration.properties.cors.allowedOrigins',[])},'fail':{'kind':kind,**nest('configuration.properties.cors.allowedOrigins',['*'])}}
    _cors(_query,_selector)
SOURCE_QUERIES.update(appservice_function_app_cors_prohibit_public_access=SOURCE_QUERIES['appservice_function_app_cors_no_star'],appservice_web_app_cors_prohibit_public_access=SOURCE_QUERIES['appservice_web_app_cors_no_star'])


@_port('appservice_web_app_diagnostic_logs_enabled')
def diagnostic_flags(item,index):
    if not applicable(item,'web'):return 'NOT_APPLICABLE',{'reason':'Outside source web table'}
    flags={field:get(item,'configuration.properties.'+field,bool) for field in ('detailedErrorLoggingEnabled','httpLoggingEnabled','requestTracingEnabled')}
    return result(not all(flags.values()),flags=flags,semantics='Exact three-flag conjunction, separate from diagnostic category and destination checks')
CASES[SOURCE_QUERIES['appservice_web_app_diagnostic_logs_enabled']]={'pass':{'kind':'app','configuration':{'properties':dict.fromkeys(('detailedErrorLoggingEnabled','httpLoggingEnabled','requestTracingEnabled'),True)}},'fail':{'kind':'app','configuration':{'properties':dict.fromkeys(('detailedErrorLoggingEnabled','httpLoggingEnabled','requestTracingEnabled'),False)}}}


@_port('appservice_web_app_health_check_enabled')
def health_path(item,index):
    if not applicable(item,'web'):return 'NOT_APPLICABLE',{'reason':'Outside source web table'}
    path=get(item,'configuration.properties.healthCheckPath')
    if path is not None and not isinstance(path,str):raise Unavailable('Malformed health-check path')
    return result(path is None,path_declared=path is not None,semantics='Exact source non-null path; no HTTP health probe or delivery assertion')
CASES[SOURCE_QUERIES['appservice_web_app_health_check_enabled']]={'pass':{'kind':'app',**nest('configuration.properties.healthCheckPath','/health')},'fail':{'kind':'app',**nest('configuration.properties.healthCheckPath',None)}}


@_port('appservice_web_app_slot_use_https','app_service_slot')
def slot_https(item,index):return result(not get(item,'properties.httpsOnly',bool),semantics='Authoritative slot metadata, separate native ARM slot identity')
CASES[SOURCE_QUERIES['appservice_web_app_slot_use_https']]={'pass':nest('properties.httpsOnly',True),'fail':nest('properties.httpsOnly',False)}


@_port('appservice_plan_minimum_sku','app_service_plan')
def plan_sku(item,index):
    sku=get(item,'sku.name',str)
    if not sku:raise Unavailable('Empty SKU')
    return result(sku in ('F1','D1','B1','B2','B3'),sku=sku,semantics='Pinned SKU deny list; no unsupported production/availability guarantee')
CASES[SOURCE_QUERIES['appservice_plan_minimum_sku']]={'pass':nest('sku.name','P1v3'),'fail':nest('sku.name','B1')}


RUNTIMES={
'appservice_function_app_latest_java_version':('function','java','Java','21'),
'appservice_web_app_latest_java_version':('app','java','JAVA','21'),
'appservice_web_app_latest_php_version':('app_linux','php','PHP','PHP|8.4'),
'appservice_function_app_latest_python_version':('function_linux','python','Python','Python|3.12'),
'appservice_web_app_latest_python_version':('app_linux','python','PYTHON','PYTHON|3.13'),
}


def _runtime(query,spec):
    selector,language,prefix,baseline=spec
    @_port(query)
    def evaluate(item,index):
        if not applicable(item,selector):return 'NOT_APPLICABLE',{'reason':'Outside exact source runtime applicability'}
        parameters=index.get('context',{}).get('metadata',{}).get('source_parameters',{})
        if not isinstance(parameters,dict):raise Unavailable('Malformed captured source parameters')
        wanted=parameters.get(query,baseline)
        pattern=r'\d+(?:\.\d+)*' if language=='java' else re.escape(prefix)+r'\|\d+(?:\.\d+)*'
        if not isinstance(wanted,str) or not re.fullmatch(pattern,wanted):raise Unavailable('Unresolved/malformed literal runtime baseline parameter')
        config=get(item,'configuration.properties',dict);fx=get(config,'linuxFxVersion')
        if fx is not None and not isinstance(fx,str):raise Unavailable('Malformed Linux runtime')
        # SQL LIKE comparisons are case-sensitive and three-valued. Preserve
        # supplied baseline values, rather than silently asserting today's latest.
        if language=='java':
            java=get(config,'javaVersion');other=get(config,'javaContainer') if selector=='app' else java
            if java is not None and not isinstance(java,str):raise Unavailable('Malformed Java version')
            if other is not None and not isinstance(other,str):raise Unavailable('Malformed Java container')
            if fx is None and java is None:raise Unavailable('Legacy Java runtime context unavailable; modern/Flex/native constraints cannot be inferred')
            not_used=isinstance(fx,str) and not fx.startswith(prefix) and other is None
            good=not_used or isinstance(fx,str) and fx.endswith(wanted) or java==wanted
        else:
            if fx is None:raise Unavailable('Legacy Linux runtime context unavailable; modern/Flex/native constraints cannot be inferred')
            good=not fx.startswith(prefix) or fx==wanted
        return result(not good,linux_runtime=fx,pinned_baseline=wanted,semantics='Literal resolved source parameter and case-sensitive classifier; not a claim of current latest version or end-of-support assessment')
    kind='functionapp,linux' if selector.startswith('function') else 'app,linux'
    field={'java':'JAVA|','php':'PHP|','python':'PYTHON|'}[language]
    fx=prefix+'|'+baseline if language=='java' else baseline
    def fixture(value):return {'kind':kind,'configuration':{'properties':{'linuxFxVersion':value,'javaVersion':None,'javaContainer':None}}}
    CASES[SOURCE_QUERIES[query]]={'pass':fixture(fx),'fail':fixture(prefix+'|0.0')}
for _q,_s in RUNTIMES.items():_runtime(_q,_s)
