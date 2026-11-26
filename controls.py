"""Versioned synthetic ITGC rules; not organization-approved controls."""
from types import MappingProxyType
from gaiasox import evaluate

REGISTRY = MappingProxyType({
    'ACCESS-001': ('1.0.0', 'approved'),
    'OFFBOARD-001': ('1.0.0', 'disabled'),
    'PASSWORD-001': ('1.0.0', 'policy_enforced'),
    'BACKUP-001': ('1.0.0', 'within_approved_window'),
    'TLS-001': ('1.0.0', 'encrypted'),
})

def collect_synthetic(control_id, version, rows, expected_ids):
    if control_id not in REGISTRY or REGISTRY[control_id][0] != version:
        raise ValueError('unknown control version')
    field = REGISTRY[control_id][1]
    normalized = None
    if isinstance(rows, list) and all(isinstance(r, dict) for r in rows):
        normalized = [{'id': r.get('id'), 'approved': r.get(field)} for r in rows]
    return {'control': control_id, 'version': version, 'source': 'synthetic',
            'rows': rows, 'expected_ids': expected_ids,
            'result': evaluate(normalized, expected_ids)}
