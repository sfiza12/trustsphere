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

# -----------------------------------------------------------------------------
# SCORING PARAMETERS & LIMITS
# -----------------------------------------------------------------------------
# DIMENSION_CAP: The absolute maximum penalty points that any single detection 
# engine can deduct in a single evaluation cycle. This is a critical security 
# mechanism preventing any one faulty engine (e.g. an over-sensitive ML model) 
# from single-handedly dominating the score and crashing a device to 0 instantly.
DIMENSION_CAP = 30

# RECOVERY_PER_CLEAN_HOUR: The amount of trust score points a device regains 
# naturally if it completes a full evaluation cycle with exactly 0 penalties 
# across all engines. This organic "healing" mechanism penalizes short-term spikes
# while rewarding long-term consistent good behavior.
RECOVERY_PER_CLEAN_HOUR = 5

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
    
    # 1. Total geometric penalty is the absolute sum of all three distinct dimensions.
    # Note: Engines intrinsically cap their own outputs at DIMENSION_CAP internally 
    # prior to passing values to this function.
    total_penalty = hard_penalty + drift_penalty + ml_penalty
    
    # 2. Mathematical application.
    # The max(0, ...) boundary enforcement ensures the score cannot logically 
    # drop below Absolute Zero into negative integer bounds, which would break UI.
    new_score = max(0, current_score - total_penalty)
    
    # 3. Request classification tier natively
    severity = get_severity(new_score)
    
    # Rounding normalizes floating point artifacts before database storage
    return round(new_score, 2), severity

def apply_recovery(current_score):
    """
    The passive healing mechanism. Triggered explicitly by the main architectural 
    orchestrator ONLY if hard_penalty + drift_penalty + ml_penalty == 0.
    
    Args:
        current_score (float): The active score requiring healing.
        
    Returns:
        float: The healed score, capped cleanly at the structural max ceiling of 100.
    """
    # The min(100, ...) boundary enforcement ensures the device cannot logically 
    # accumulate "infinite trust" above a perfect 100 percent maximum.
    recovered = min(100, current_score + RECOVERY_PER_CLEAN_HOUR)
    return round(recovered, 2)