"""Native read contracts for Entra custom-role structural consumers."""
from copy import deepcopy
from urllib.parse import parse_qs, urlsplit
from peaso.azure_unused_iam_contract import GRAPH, guid

KIND = 'azure_unused_role_evidence'
SCHEMA = 'azure-unused-role-evidence-v1'
REPORTS = {
    'assignments': '/v1.0/roleManagement/directory/roleAssignments',
    'assignment_schedules': '/v1.0/roleManagement/directory/roleAssignmentSchedules',
    'eligibility_schedules': '/v1.0/roleManagement/directory/roleEligibilitySchedules',
}
MAX_ROWS = 100000
FIELDS = ('id', 'roleDefinitionId', 'principalId', 'directoryScopeId', 'appScopeId', 'status', 'memberType')


def required_types(wanted):
    return {'directory_role_definition'} if KIND in wanted else set()


def validate_read(url, endpoint, *, audience=GRAPH, body=None):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (body is not None or audience != GRAPH or parsed.scheme != 'https' or parsed.netloc != 'graph.microsoft.com'
            or parsed.path != endpoint or parsed.fragment or any(key not in ('$skiptoken', '$skipToken', '$top') for key in query)
            or any(len(values) != 1 or not values[0] for values in query.values())
            or '$top' in query and (not query['$top'][0].isdigit() or not 1 <= int(query['$top'][0]) <= 999)):
        raise ValueError('unfiltered native role-assignment source changed')


def project(row):
    if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not row['id']:
        raise ValueError('native role consumer ID is unavailable')
    guid(row.get('roleDefinitionId'));guid(row.get('principalId'))
    output = {key: deepcopy(row[key]) for key in FIELDS if key in row}
    if '_coverage' in row: output['_coverage'] = deepcopy(row['_coverage'])
    if 'scheduleInfo' in row:
        schedule = row['scheduleInfo']
        if not isinstance(schedule, dict): raise ValueError('native role schedule is malformed')
        value = {key: deepcopy(schedule[key]) for key in ('startDateTime',) if key in schedule}
        if 'expiration' in schedule:
            expiration = schedule['expiration']
            if not isinstance(expiration, dict): raise ValueError('native role expiration is malformed')
            value['expiration'] = {key: deepcopy(expiration[key]) for key in ('type', 'endDateTime', 'duration') if key in expiration}
        output['scheduleInfo'] = value
    return output
