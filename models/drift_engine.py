# =============================================================================
# DRIFT DETECTION ENGINE MODULE — TrustSphere
# =============================================================================
# This mathematical engine isolates and calculates statistical behavioral drift.
# It computes percentage-based deviations continuously by comparing immediate 
# live device behavior against its historically established baseline norms.
#
# Unlike Hard Violations (which check static rules), the Drift Engine is entirely 
# relative to the device's own individual history. What is a "spike" for one 
# device might be "normal" for another dynamically.
# =============================================================================

import sys
import os
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import SPIKE_THRESHOLD, DRIFT_THRESHOLD, SUSTAINED_HOURS

def calculate_drift(current_value, baseline_value):
    """
    Core fundamental mathematical calculation for establishing relative drift percentages.
    Formula: ((current - baseline) / baseline)
    
    Args:
        current_value (float/int): The observed value happening right now.
        baseline_value (float/int): The trusted normative value learned over time.
        
    Returns:
        float: The calculated drift represented as a raw decimal 
               (e.g., 0.45 equals a +45% jump above baseline, 
               -0.20 equals a -20% dip below baseline).
    """
    # Guard logic to gracefully prevent mathematical divide-by-zero exceptions
    if not baseline_value or baseline_value == 0:
        return 0.0
    
    try:
        drift = (float(current_value) - float(baseline_value)) / float(baseline_value)
        return float(drift)
    except Exception as e:
        logging.error(f"Error calculating drift: {e}")
        return 0.0

def check_drift(device_row, current_packets, current_failed, current_unique_ips):
    """
    The orchestrator function for evaluating a specific snapshot in time across 
    multiple varying statistical dimensions.
    
    Args:
        device_row (dict): Contains the current state tracking variables including baselines.
        current_packets (float): Incoming row's packet transmission volume.
        current_failed (int): Incoming row's failed TCP handshakes or drop count.
        current_unique_ips (int): Variety depth of destination communication targets.
        
    Returns:
        tuple: (penalty: int, drift_type: str, reasons: list[str], new_streak: int)
               Provides aggregated deductions, the categorization of event (spike/sustained), 
               human-readable explanations, and the incremented/reset mathematical continuity counter.
    """
    
    penalty = 0
    reasons = []
    drift_type = "none"
    
    try:
        # -------------------------------------------------------------------------
        # HISTORICAL BASELINE EXTRACTION
        # -------------------------------------------------------------------------
        baseline_packets = device_row.get('baseline_packets')
        baseline_failed = device_row.get('baseline_failed')
        baseline_unique_ips = device_row.get('baseline_unique_ips')
        current_streak = device_row.get('drift_streak') or 0

        # -------------------------------------------------------------------------
        # DEPENDENCY CHECK
        # -------------------------------------------------------------------------
        # Drift cannot physically be calculated if the system has not yet established 
        # what "normal" looks like for this precise device identifier.
        if baseline_packets is None:
            return 0, "no_baseline", [], current_streak

        # -------------------------------------------------------------------------
        # PERCENTAGE COMPUTATIONS
        # -------------------------------------------------------------------------
        packet_drift = calculate_drift(current_packets, baseline_packets)
        failed_drift = calculate_drift(current_failed, baseline_failed) if baseline_failed else 0
        ip_drift = calculate_drift(current_unique_ips, baseline_unique_ips) if baseline_unique_ips else 0

        # Retrieve absolute magnitude for comparison because crashing to 0 packets 
        # when normally at 50 is just as suspicious as spiking to 100.
        abs_packet_drift = abs(packet_drift) 

        # -------------------------------------------------------------------------
        # EVALUATION 1: SINGLE EVENT MASSIVE SPIKE DETECTION
        # -------------------------------------------------------------------------
        if abs_packet_drift > SPIKE_THRESHOLD:
            penalty += 15
            direction = "increase" if packet_drift > 0 else "decrease"
            reasons.append(
                f"Sudden traffic {direction} definitively detected: "
                f"{abs_packet_drift*100:.1f}% mathematical deviation away from strict baseline "
                f"({baseline_packets:.0f} -> {float(current_packets):.0f} packets/min measured). "
                f"Explicitly exceeds severe event spike threshold limit of {SPIKE_THRESHOLD*100:.0f}%."
            )
            drift_type = "spike"
            # Since a spike is viewed as a singular massive anomaly, it structurally cancels 
            # any active sustained subtle drift streak accumulation.
            new_streak = 0  

        # -------------------------------------------------------------------------
        # EVALUATION 2: SUSTAINED SUBTLE DRIFT DETECTION
        # -------------------------------------------------------------------------
        # If not a spike, is it a moderate deviation?
        elif abs_packet_drift > DRIFT_THRESHOLD:
            # Increment the continuous historical time-block counter tracking persistence
            new_streak = current_streak + 1  
            
            if new_streak >= SUSTAINED_HOURS:
                # The device has been acting slightly abnormally continuously for an extended duration.
                # This triggers a larger penalty structurally associated with confirmed sustained shifts.
                penalty += 20
                direction = "increase" if packet_drift > 0 else "decrease"
                reasons.append(
                    f"Sustained behavioral traffic drift analytically confirmed: "
                    f"{abs_packet_drift*100:.1f}% {direction} from norm "
                    f"for {new_streak} consecutive contiguous hours. "
                    f"Formal Baseline: {baseline_packets:.0f} packets/min | "
                    f"Current Snapshot: {float(current_packets):.0f} packets/min."
                )
                drift_type = "sustained"
            else:
                # The device is acting slightly weird, but hasn't done it long enough to confirm. 
                # We apply a gentle penalty warning.
                penalty += 5
                reasons.append(
                    f"Early drift signal active: {abs_packet_drift*100:.1f}% analytical deviation "
                    f"from baseline behavior (currently observing hour {new_streak} out of {SUSTAINED_HOURS} limit required for confirmation)."
                )
                drift_type = "early"
        else:
            # The behavior is within highly acceptable statistical margins. 
            # We mathematically terminate the persistence counter, forgiving previous subtle anomalies.
            new_streak = 0

        # -------------------------------------------------------------------------
        # EVALUATION 3: COMMUNICATION SURFACE AREA EXPANSION
        # -------------------------------------------------------------------------
        # Checks if the device is suddenly talking to significantly more distinct endpoints.
        # Highly characteristic of botnet recruitment attempting lateral movement mapping internally.
        if baseline_unique_ips and ip_drift > DRIFT_THRESHOLD:
            penalty += 10
            reasons.append(
                f"Communication surface architectural expansion detected: Device is newly communicating "
                f"with {float(current_unique_ips):.0f} distinct unique destination IPs against an established baseline norm of "
                f"{baseline_unique_ips:.0f} IPs "
                f"({ip_drift*100:.1f}% structural increase)."
            )
            
    except Exception as e:
        logging.error(f"Error executing drift analysis: {e}")
        # Soft fallback
        new_streak = device_row.get('drift_streak') or 0

    # -------------------------------------------------------------------------
    # AGGREGATION & CAPPING
    # -------------------------------------------------------------------------
    # Structurally restricts the theoretical maximum loss of trust score from the 
    # Drift Engine dimension to precisely 30 points per singular chronological assessment row.
    penalty = min(penalty, 30)

    return penalty, drift_type, reasons, new_streak