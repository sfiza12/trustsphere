# =============================================================================
# TRUST SCORE AGGREGATION ENGINE — TrustSphere
# =============================================================================
# This module acts as the central aggregator and final authority for the device's 
# overall Trust Score. It receives individual calculated penalties from all three 
# detection engines (Violation, Drift, ML) and combines them into a single metric.
# 
# This is explicitly the ONLY place in the architecture where the overarching 
# trust score math is applied or modified.
# =============================================================================

import logging

from config import DIMENSION_CAP, RECOVERY_PER_CLEAN_HOUR  # type: ignore

def get_severity(score):
    """
    Categorical mapper that translates a continuous numerical trust score (0-100) 
    into a discrete, human-readable qualitative severity tier for dashboard rendering.
    
    Tiers are structurally defined as:
    - 80 to 100: Trusted (Green)
    - 60 to  79: Low Risk (Yellow)
    - 40 to  59: Medium Risk (Orange)
    - 20 to  39: High Risk (Red)
    -  0 to  19: Critical (Dark Red / Black)
    
    Args:
        score (float/int): The numerical device trust score.
        
    Returns:
        str: The categorical severity label.
    """
    if score >= 80:
        return "Trusted"
    elif score >= 60:
        return "Low Risk"
    elif score >= 40:
        return "Medium Risk"
    elif score >= 20:
        return "High Risk"
    else:
        return "Critical"

def calculate_trust_score(current_score, hard_penalty, drift_penalty, ml_penalty):
    """
    The core aggregation junction. Combines independent penalty streams and applies 
    them deductively against the device's running historical trust score.
    
    Args:
        current_score (float): The trust score the device currently holds prior to this tick.
        hard_penalty (int): Deduction passed from the deterministic Violation Engine.
        drift_penalty (int): Deduction passed from the statistical Drift Engine.
        ml_penalty (int): Deduction passed from the probabilistic ML Isolation Forest.
        
    Returns:
        tuple: (new_score: float, severity: str)
               Rounded numeric score bounded at 0, and its corresponding categorical tag.
    """
    
    try:
        # 1. Total geometric penalty is the absolute sum of all three distinct dimensions.
        # Note: Engines intrinsically cap their own outputs at DIMENSION_CAP internally 
        # prior to passing values to this function.
        # Here we cap them defensively just in case the engine didn't.
        total_penalty = min(hard_penalty, DIMENSION_CAP) + min(drift_penalty, DIMENSION_CAP) + min(ml_penalty, DIMENSION_CAP)
        
        # 2. Mathematical application.
        # The max(0, ...) boundary enforcement ensures the score cannot logically 
        # drop below Absolute Zero into negative integer bounds, which would break UI.
        new_score = max(0.0, float(current_score) - float(total_penalty))  # type: ignore
        
        # 3. Request classification tier natively
        severity = get_severity(new_score)
        
        # Rounding normalizes floating point artifacts before database storage
        return round(float(new_score), 2), severity  # type: ignore
    except Exception as e:
        logging.error(f"Error calculating trust score: {e}")
        return current_score, get_severity(current_score)

def apply_recovery(current_score):
    """
    The passive healing mechanism. Triggered explicitly by the main architectural 
    orchestrator ONLY if hard_penalty + drift_penalty + ml_penalty == 0.
    
    Args:
        current_score (float): The active score requiring healing.
        
    Returns:
        float: The healed score, capped cleanly at the structural max ceiling of 100.
    """
    try:
        # The min(100, ...) boundary enforcement ensures the device cannot logically 
        # accumulate "infinite trust" above a perfect 100 percent maximum.
        recovered = min(100.0, float(current_score) + float(RECOVERY_PER_CLEAN_HOUR))  # type: ignore
        return round(float(recovered), 2)  # type: ignore
    except Exception as e:
        logging.error(f"Error applying recovery calculation: {e}")
        return float(current_score)