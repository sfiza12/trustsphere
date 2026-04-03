import pytest
from models.drift_engine import evaluate_drift

def test_drift_holding_pattern_activation():
    """ Tests the Observation Strategy where sudden spikes do not immediately penalize. """
    row = {'packets_per_min': 1000}
    baseline = {'baseline_packets': 10}
    
    # 0 previous streak
    penalty, streak = evaluate_drift(row, baseline, 0)
    
    assert streak == 1, "Expected drift streak to increment."
    assert penalty == 0, "Expected penalty to be perfectly 0 during the Observation Phase."

def test_drift_sustained_penalty():
    """ Tests that penalties are forcefully applied after consecutive drift units. """
    row = {'packets_per_min': 1000}
    baseline = {'baseline_packets': 10}
    
    # Sustained drift sequence (e.g. 5 hours)
    penalty, streak = evaluate_drift(row, baseline, 5)
    
    assert streak == 6, "Expected drift streak to continue incrementing."
    assert penalty > 0, "Expected active penalty since Observation limits were breached."

def test_drift_recovery():
    """ Tests that the streak seamlessly drops to 0 when returned to baseline margins. """
    row = {'packets_per_min': 11} # Totally normal
    baseline = {'baseline_packets': 10}
    
    penalty, streak = evaluate_drift(row, baseline, 5)
    
    assert streak == 0, "Expected drift streak to completely wipe upon normalized behavior."
    assert penalty == 0, "Expected penalty to drop mathematically to 0."
