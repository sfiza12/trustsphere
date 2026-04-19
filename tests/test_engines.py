import os
import sys
import pytest

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.violation_engine import check_violations
from models.drift_engine import check_drift, calculate_drift
from models.trust_score import calculate_trust_score, apply_recovery, get_severity
from models.baseline_manager import (
    should_update_baseline,
    calculate_new_baseline,
    initialize_baseline
)

# HELPER
def make_device_row(baseline_packets, streak=0):
    """
    Returns a dictionary simulating a device database row.
    """
    return {
        'baseline_packets': baseline_packets,
        'baseline_failed': 2.0,
        'baseline_unique_ips': 1.0,
        'drift_streak': streak,
        'confirmation_days': 0  # Added for baseline manager tests
    }

# --- VIOLATION ENGINE TESTS ---

def test_no_violation():
    # Row: port=443, ip=192.168.1.10, failed=5, packets=100
    row = {
        'port_used': 443,
        'destination_ip': '192.168.1.10',
        'failed_connections': 5,
        'packets_per_min': 100
    }
    penalty, _ = check_violations(row)
    assert penalty == 0

def test_unauthorized_port():
    # Row: port=6667, ip=192.168.1.10, failed=5, packets=100
    row = {
        'port_used': 6667,
        'destination_ip': '192.168.1.10',
        'failed_connections': 5,
        'packets_per_min': 100
    }
    penalty, _ = check_violations(row)
    assert penalty > 0

def test_unapproved_ip():
    # Row: port=443, ip=185.99.12.34, failed=5, packets=100
    row = {
        'port_used': 443,
        'destination_ip': '185.99.12.34',
        'failed_connections': 5,
        'packets_per_min': 100
    }
    penalty, _ = check_violations(row)
    assert penalty > 0

def test_excessive_failed_connections():
    # Row: port=443, ip=192.168.1.10, failed=60, packets=100
    row = {
        'port_used': 443,
        'destination_ip': '192.168.1.10',
        'failed_connections': 60,
        'packets_per_min': 100
    }
    penalty, _ = check_violations(row)
    assert penalty > 0

def test_all_violations_capped_at_30():
    # Row: port=6667, ip=185.99.12.34, failed=60, packets=600
    row = {
        'port_used': 6667,
        'destination_ip': '185.99.12.34',
        'failed_connections': 60,
        'packets_per_min': 600
    }
    penalty, _ = check_violations(row)
    assert penalty == 30

# --- DRIFT ENGINE TESTS ---

def test_calculate_drift_formula():
    # calculate_drift(current=68, baseline=50)
    result = calculate_drift(68, 50)
    assert result == pytest.approx(0.36, rel=0.01)

def test_no_drift_within_threshold():
    # Device: baseline_packets=50, current=52 (4% drift), streak=0
    row = make_device_row(50, 0)
    penalty, drift_type, reasons, new_streak = check_drift(row, 52, 2.0, 1.0)
    assert penalty == 0
    assert new_streak == 0

def test_early_drift_detected():
    # Device: baseline_packets=50, current=68 (36% drift), streak=0
    row = make_device_row(50, 0)
    penalty, drift_type, reasons, new_streak = check_drift(row, 68, 2.0, 1.0)
    assert penalty == 5
    assert new_streak == 1
    assert drift_type == "early"

def test_spike_detection():
    # Device: baseline_packets=50, current=80 (60% drift), streak=0
    row = make_device_row(50, 0)
    penalty, drift_type, reasons, new_streak = check_drift(row, 80, 2.0, 1.0)
    assert penalty == 15
    assert drift_type == "spike"
    assert new_streak == 0

def test_sustained_drift_confirmed_at_6_hours():
    # Device: baseline_packets=50, current=68 (36% drift), streak=5
    # Assumes SUSTAINED_HOURS is 6 (streak 5 -> 6 triggers sustained)
    row = make_device_row(50, 5)
    penalty, drift_type, reasons, new_streak = check_drift(row, 68, 2.0, 1.0)
    assert penalty == 20
    assert new_streak == 6
    assert drift_type == "sustained"

def test_streak_resets_on_normal_behavior():
    # Device: baseline_packets=50, current=52 (4% drift), streak=4
    row = make_device_row(50, 4)
    penalty, drift_type, reasons, new_streak = check_drift(row, 52, 2.0, 1.0)
    assert new_streak == 0
    assert penalty == 0

# --- TRUST SCORE TESTS ---

def test_score_decreases_with_penalty():
    # current_score=100, hard=10, drift=5, ml=0
    new_score, severity = calculate_trust_score(100, 10, 5, 0)
    assert new_score == 85

def test_score_never_goes_negative():
    # current_score=10, hard=30, drift=30, ml=30
    new_score, severity = calculate_trust_score(10, 30, 30, 30)
    assert new_score == 0

def test_recovery_adds_5_points():
    # apply_recovery(80)
    # Assumes RECOVERY_PER_CLEAN_HOUR = 5
    result = apply_recovery(80)
    assert result == 85

def test_recovery_capped_at_100():
    # apply_recovery(98)
    result = apply_recovery(98)
    assert result == 100

def test_severity_bands():
    assert get_severity(95) == "Trusted"
    assert get_severity(70) == "Low Risk"
    assert get_severity(50) == "Medium Risk"
    assert get_severity(30) == "High Risk"
    assert get_severity(10) == "Critical"

# --- BASELINE MANAGER TESTS ---

def test_no_update_during_hard_violation():
    # has_hard_violation=True, drift_streak=10, confirmation_days=10
    row = {
        'drift_streak': 10,
        'confirmation_days': 10
    }
    should_update, new_confirmation = should_update_baseline(row, 0, 0, 0, True)
    assert should_update == False
    assert new_confirmation == 0

def test_no_update_when_streak_too_low():
    # has_hard_violation=False, drift_streak=3, confirmation_days=0
    # Assumes DRIFT_HOURS_BEFORE_CONFIRMATION > 3 (e.g. 6)
    row = {
        'drift_streak': 3,
        'confirmation_days': 0
    }
    should_update, new_confirmation = should_update_baseline(row, 0, 0, 0, False)
    assert should_update == False

def test_update_after_full_confirmation():
    # has_hard_violation=False, drift_streak=6, confirmation_days=5
    # Assumes DRIFT_HOURS_BEFORE_CONFIRMATION=6 and CONFIRMATION_HOURS_REQUIRED=6
    row = {
        'drift_streak': 6,
        'confirmation_days': 5
    }
    should_update, new_confirmation = should_update_baseline(row, 0, 0, 0, False)
    assert should_update == True

def test_confirmation_increments_correctly():
    # has_hard_violation=False, drift_streak=6, confirmation_days=2
    row = {
        'drift_streak': 6,
        'confirmation_days': 2
    }
    should_update, new_confirmation = should_update_baseline(row, 0, 0, 0, False)
    assert should_update == False
    assert new_confirmation == 3

def test_calculate_new_baseline_shifts_10_percent():
    # old_baseline=100, current_value=140. Formula: 100 + (140-100)*0.10 = 104
    result = calculate_new_baseline(100, 140)
    assert result == pytest.approx(104.0)

def test_calculate_new_baseline_downward():
    # old_baseline=100, current_value=60. Formula: 100 + (60-100)*0.10 = 96
    result = calculate_new_baseline(100, 60)
    assert result == pytest.approx(96.0)

def test_initialize_baseline_sets_correctly():
    # packets=50, failed=5, unique_ips=2
    result = initialize_baseline(50, 5, 2)
    assert result['baseline_packets'] == 50.0
    assert result['baseline_failed'] == 5.0
    assert result['baseline_unique_ips'] == 2.0
