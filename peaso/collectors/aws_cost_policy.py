"""Owner-declared cost alert intent, separate from observed subscriptions."""

OPTION = 'compliance_parameters'
KEY = 'cost_anomaly_alerts'


def normalize(options):
    parameters = options.get(OPTION, {})
    if not isinstance(parameters, dict):
        raise ValueError('compliance parameters must be an object')
    if KEY not in parameters:
        return None
    value = parameters[KEY]
    allowed = {'approved_recipients', 'cost_allocation_tag_key', 'prod_tag_value', 'qa_tag_value'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError('invalid cost anomaly owner policy fields')
    recipients = value.get('approved_recipients')
    def text(v):
        return isinstance(v, str) and 0 < len(v) <= 1024 and v == v.strip() and not any(ord(c) < 32 for c in v)
    if (not isinstance(recipients, list) or not 0 < len(recipients) <= 1000
            or any(not text(v) for v in recipients) or len(recipients) != len(set(recipients))):
        raise ValueError('invalid approved cost alert recipients')
    if any(not text(v) for k,v in value.items() if k != 'approved_recipients'):
        raise ValueError('invalid cost allocation tag policy')
    if ('prod_tag_value' in value or 'qa_tag_value' in value) and 'cost_allocation_tag_key' not in value:
        raise ValueError('cost allocation tag key is required')
    return {**value, 'approved_recipients': list(recipients), 'status': 'collected',
            'source': 'owner_declared_policy', 'delivery_verified': False}
