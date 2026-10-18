"""Actual collector ordering retains fresh diagnostics after ETag-bound refresh."""
from urllib.parse import urlsplit
from peaso.collectors import azure
from tests import test_peaso_azure_public_edge_native as original
from tests.test_peaso_azure_bulk_native import envelope


def test_native_edge_refresh_precedes_fresh_diagnostic_enrichment(monkeypatch):
    original_collect=azure.collect
    original_transport=original.Transport
    observed=[]
    diagnostic_id=original.LB+'/providers/Microsoft.Insights/diagnosticSettings/current'
    category_id=original.LB+'/providers/Microsoft.Insights/diagnosticSettingsCategories/LoadBalancerAlertEvent'
    class Transport(original_transport):
        def __init__(self,routes):
            super().__init__(routes)
            self.routes[original.SCOPE+'/resources']={'value':[{'id':original.LB,'type':original.edge.TYPES['load_balancer']},{'id':original.IP,'type':original.edge.TYPES['public_ip']}]}
            list_row=self.routes[original.SCOPE+'/providers/Microsoft.Network/loadBalancers']['value'][0]
            list_row['diagnosticSettings']=[{'id':'stale-list-diagnostic-never-copy'}]
            list_row['diagnosticCategories']=[{'id':'stale-list-category-never-copy'}]
            list_row['_coverage']={'diagnosticSettings':{'status':'partial'},'diagnosticCategories':{'status':'partial'}}
            self.routes[original.LB]['etag']='W/"fresh-lb-native-v4"'
            self.routes[original.LB+'/providers/Microsoft.Insights/diagnosticSettings']={'value':[{'id':diagnostic_id,'name':'current','type':'Microsoft.Insights/diagnosticSettings','properties':{'logs':[{'category':'LoadBalancerAlertEvent','enabled':True}],'workspaceId':original.BASE+'Microsoft.OperationalInsights/workspaces/current'}}]}
            self.routes[original.LB+'/providers/Microsoft.Insights/diagnosticSettingsCategories']={'value':[{'id':category_id,'name':'LoadBalancerAlertEvent','type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['allLogs']}}]}
        def request(self,url,*,body=None,audience=azure.ARM):
            path=urlsplit(url).path
            if path==original.LB:observed.append('fresh_native_lb_get')
            if path.startswith(original.LB+'/providers/Microsoft.Insights/'):
                assert 'fresh_native_lb_get' in observed,'Diagnostic request preceded authoritative parent refresh'
                observed.append(path.rsplit('/',1)[-1])
            return super().request(url,body=body,audience=audience)
    def composed(connector,requirements,**kwargs):
        return original_collect(connector,[*requirements,'diagnostic_setting','diagnostic_category'],**kwargs)
    monkeypatch.setattr(original,'Transport',Transport)
    monkeypatch.setattr(azure,'collect',composed)
    snapshot,status,_=original.capture('get_etag_changed')
    assert status=='PASS'
    row=envelope(snapshot,'load_balancer')['items'][0]
    assert row['etag']=='W/"fresh-lb-native-v4"'
    assert [value['id'] for value in row['diagnosticSettings']]==[diagnostic_id]
    assert [value['id'] for value in row['diagnosticCategories']]==[category_id]
    assert row['_coverage']['diagnosticSettings']['status']=='collected'
    assert row['_coverage']['diagnosticCategories']['status']=='collected'
    binding=next(row for row in envelope(snapshot,'public_edge_binding')['items']if row['resource_kind']=='load_balancer')
    assert binding['resource_etag']==row['etag']
    assert observed.index('fresh_native_lb_get')<observed.index('diagnosticSettings')<observed.index('diagnosticSettingsCategories')
    assert all('stale-list-' not in value['id'] for key in ['diagnosticSettings','diagnosticCategories']for value in row[key])
