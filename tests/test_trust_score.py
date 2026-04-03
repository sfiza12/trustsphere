import pytest
from models.trust_score import evaluate_trust_score, apply_recovery

def test_trust_score_boundary_floor():
    """ Ensure trust scores can never dip below mathematically absolute zero. """
    current_score = 10
    
    # Inject massive penalties across the board
    new_score, severity = evaluate_trust_score(current_score, hard_penalty=50, drift_penalty=50, ml_penalty=50)
    
    assert new_score == 0.0, "The score dropped into negative bounds, which breaks the UI scale. Floor failed."
    assert severity == "Critical", "Expected Critical severity for zero score."

def test_trust_score_boundary_ceiling():
    """ Ensure healing logic can never boost scores into impossible >100 parameters. """
    current_score = 98.0
    
    healed_score = apply_recovery(current_score)
    
    assert healed_score == 100.0, "Score bypassed the 100.0 maximum limits. Ceiling failed."

def test_trust_score_normal_decrement():
    """ Geometric combination of penalties across engines. """
    current_score = 100.0
    # Engine logic generally caps internally at 30
    new_score, severity = evaluate_trust_score(current_score, hard_penalty=10, drift_penalty=5, ml_penalty=5)
    
    # 100 - 20 = 80
    assert new_score == 80.0
    assert severity in ["Low Risk", "Medium Risk"]
