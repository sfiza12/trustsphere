# =============================================================================
# BASELINE MANAGEMENT ENGINE — TrustSphere
# =============================================================================
# This module implements the "Self-Healing" and "Continuous Adaptation" logic.
# It critically governs EXACTLY when and how a device's formal mathematical baseline 
# is allowed to be rewritten by new, drifted behavior.
#
# This explicitly exists to prevent "Baseline Poisoning" attacks (where an attacker 
# gradually ramps up traffic to force the system into accepting malicious volume as normal) 
# by enforcing strict time-delay observation windows and hard violation blocking. 
# =============================================================================

import sys
import os
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import DRIFT_HOURS_BEFORE_CONFIRMATION, CONFIRMATION_HOURS_REQUIRED, BASELINE_SHIFT_RATE

def should_update_baseline(device_row, current_packets, current_failed, 
                           current_unique_ips, has_hard_violation):
    """
    Evaluates the strict conditional logic determining if a baseline is authorized 
    to be gradually adjusted during this specific evaluation row interval.
    
    Security Rules Modeled:
    1. Sustained drift must mathematically exist first (drift_streak >= 3).
    2. A formal holding confirmation window must elapse cleanly.
    3. Absolutely NO active hard corporate policy violations can exist.
    
    Args:
        device_row (dict): System state persistence object.
        current_packets (float): Current bandwidth.
        current_failed (int): Current connection failure rate.
        current_unique_ips (int): Current endpoint spreading rate.
        has_hard_violation (bool): Boolean flag denoting if deterministic policies were breached.
        
    Returns:
        tuple: (should_update: bool, new_confirmation_days: int)
               A boolean authorizing shifting logic, and the incremented observation counter.
    """
    
    # State extraction
    drift_streak = device_row['drift_streak'] or 0
    confirmation_days = device_row['confirmation_days'] or 0
    
    # -------------------------------------------------------------------------
    # SECURITY GATE 1: THE POISONING DEFENSE
    # -------------------------------------------------------------------------
    # If the device is currently breaking any explicit deterministic policy (e.g. hitting 
    # unauthorized ports, accessing known bad IPs), it is physically impossible that 
    # its new behavior is "benign". 
    # We violently abort the confirmation phase and reset the observation clock to zero.
    if has_hard_violation:
        return False, 0  
    
    # -------------------------------------------------------------------------
    # SECURITY GATE 2: THE ANOMALY PRE-REQUISITE
    # -------------------------------------------------------------------------
    # A device's baseline cannot adapt if it hasn't first exhibited sustained 
    # deviation from its original behavior. 
    if drift_streak < DRIFT_HOURS_BEFORE_CONFIRMATION:
        return False, 0
    
    # We have established sustained drift, and we are not breaking any policies.
    # We may now safely increment the Observation / Confirmation Window chronometer.
    new_confirmation_days = confirmation_days + 1
    
    # -------------------------------------------------------------------------
    # SECURITY GATE 3: THE HOLDING PATTERN ELAPSE
    # -------------------------------------------------------------------------
    # Has the device been watched long enough during this new 'weird' phase to 
    # confidently declare this new baseline as the new 'normal'?
    if new_confirmation_days >= CONFIRMATION_HOURS_REQUIRED:
        return True, new_confirmation_days
    
    # Waiting out the clock
    return False, new_confirmation_days

def calculate_new_baseline(old_baseline, current_value):
    """
    Executes the mathematical dampening function for baseline updating.
    This acts as an Exponential Moving Average (EMA) smoother.
    
    By only moving by BASELINE_SHIFT_RATE (10%), it enforces that an attacker 
    cannot suddenly train the system to accept a 500 packet jump in a single tick.
    
    Mathematical Example:
        old_baseline = 100
        current_value = 140
        difference = 40
        shift_amount = 40 * 0.10 = 4 points total
        new_baseline = 104
        
    Args:
        old_baseline (float): The previously established norm value.
        current_value (float): The sustained deviated new value target.
        
    Returns:
        float: The newly computed shifted midpoint normative baseline.
    """
    # Self-healing fallback: If the database value is null, assume immediate value.
    if old_baseline is None:
        return current_value
    
    try:
        # Calculate geometric absolute difference
        difference = float(current_value) - float(old_baseline)
        
        # Calculate fraction of allowed movement
        shift = difference * BASELINE_SHIFT_RATE
        
        # Append calculated shift delta to previous static baseline
        new_baseline = float(old_baseline) + shift
        
        return round(new_baseline, 2)
    except Exception as e:
        logging.error(f"Error calculating new baseline: {e}")
        return float(old_baseline) if old_baseline else 0.0

def initialize_baseline(packets, failed, unique_ips):
    """
    Initial onboarding sequence for newly enrolled hardware.
    Called explicitly ONLY on the very first chronological telemetry tick observed 
    for a globally unknown device MAC/Identifier. Establishes the Day-0 ground truth.
    """
    try:
        return {
            'baseline_packets': round(float(packets), 2),
            'baseline_failed': round(float(failed), 2),
            'baseline_unique_ips': round(float(unique_ips), 2) 
        }
    except Exception as e:
        logging.error(f"Error initializing baseline: {e}")
        return {
            'baseline_packets': 0.0,
            'baseline_failed': 0.0,
            'baseline_unique_ips': 0.0
        }