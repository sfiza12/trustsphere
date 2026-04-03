import pytest
from models.violation_engine import check_violations
from config import APPROVED_PORTS

def test_hard_violation_unapproved_port():
    row = {'port_used': 99999, 'packets_per_min': 10, 'failed_connections': 0, 'destination_ip': '8.8.8.8'}
    # Fails port rule directly
    penalty = check_violations(row)
    assert penalty > 0, "Expected a penalty for using an unauthorized, extremely high port."

def test_hard_violation_approved_behavior():
    row = {
        'port_used': APPROVED_PORTS[0] if APPROVED_PORTS else 443, 
        'packets_per_min': 10, 
        'failed_connections': 0, 
        'destination_ip': '192.168.1.1'
    }
    penalty = check_violations(row)
    assert penalty == 0, "Normal behavior should clear the hard violation engine with 0 penalty."

def test_hard_violation_brute_force():
    # Massive failed connection spikes indicating a brute force
    row = {'port_used': 443, 'packets_per_min': 10, 'failed_connections': 900, 'destination_ip': '8.8.8.8'}
    penalty = check_violations(row)
    assert penalty > 0, "Expected brute-force failure threshold to trigger a hard block."
