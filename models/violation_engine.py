# =============================================================================
# HARD VIOLATION ENGINE MODULE — TrustSphere
# =============================================================================
# This engine acts as the absolute deterministic rule-evaluator. It checks 
# incoming telemetry against fixed, explicitly declared corporate or security 
# policy rules.
#
# Unlike drift (which is statistical) or ML (which is probabilistic), hard 
# violations are binary — either a device definitively broke the rule, or it didn't.
# Hard violation penalties immediately clamp down on trust scores and block 
# baseline adaptation to prevent model poisoning.
# =============================================================================

import sys
import os
import logging

# Ensure we can import the config from the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import APPROVED_PORTS, APPROVED_IP_PREFIXES, MAX_FAILED_CONNECTIONS, HARD_TRAFFIC_CAP        

def check_violations(row):
    """
    Evaluates one single chronological row of raw telemetry data sequentially 
    against all configured static policy constraints.
    
    Args:
        row (dict): A dictionary mapping of the telemetry row containing keys:
            - packets_per_min (float)
            - port_used (int)
            - destination_ip (str)
            - failed_connections (int)

    Returns:
        tuple: (penalty: int, reasons: list[str])
            penalty: The aggregate calculated numeric deduction (bounded to 30 max).
            reasons: A structured list of human-readable explanation strings detailing exactly 
                     which policies were breached and why.
    """
    
    penalty = 0
    reasons = []

    try:
        # -------------------------------------------------------------------------
        # CHECK 1: PORT AUTHORIZATION
        # -------------------------------------------------------------------------
        port = int(row.get('port_used', -1))
        if port not in APPROVED_PORTS:
            penalty += 20
            reasons.append(
                f"Unauthorized port {port} detected. "
                f"Device should only use explicitly approved architectural ports: {APPROVED_PORTS}."
            )

        # -------------------------------------------------------------------------
        # CHECK 2: EXTERNAL IP REACHABILITY
        # -------------------------------------------------------------------------
        ip = str(row.get('destination_ip', 'unknown'))
        # Iterates through the approved subnet list to see if the target IP string 
        # begins with an approved prefix block
        ip_approved = any(ip.startswith(prefix) for prefix in APPROVED_IP_PREFIXES)
        
        if not ip_approved and ip != 'unknown':
            penalty += 25
            reasons.append(
                f"Communication with unauthorized exterior IP {ip}. "
                f"Device is actively attempting connections with unknown macroscopic addresses."
            )

        # -------------------------------------------------------------------------
        # CHECK 3: CONNECTION FAILURE VELOCITY
        # -------------------------------------------------------------------------
        failed = int(row.get('failed_connections', 0))
        if failed > MAX_FAILED_CONNECTIONS:
            penalty += 15
            reasons.append(
                f"Excessive volumetric failed connections: {failed}. "
                f"Policy ceiling is set at {MAX_FAILED_CONNECTIONS}. "
                f"Highly indicative of aggressive network scanning or active brute-force execution attempt."
            )

        # -------------------------------------------------------------------------
        # CHECK 4: DATA EXFILTRATION / DDOS HARD CEILING
        # -------------------------------------------------------------------------
        packets = float(row.get('packets_per_min', 0.0))
        if packets > HARD_TRAFFIC_CAP:
            penalty += 20
            reasons.append(
                f"Traffic volume ({packets} packets/min) radically exceeds standard policy cap bounds ({HARD_TRAFFIC_CAP}). "
                f"Extreme anomalous bandwidth spike definitively detected."
            )
    except Exception as e:
        logging.error(f"Error evaluating hard violations: {e}")
        # Fail safe if parsing crashes entirely
        penalty += 5
        reasons.append(f"Internal calculation parsing error during rule execution: {e}")

    # -------------------------------------------------------------------------
    # AGGREGATION & CAPPING
    # -------------------------------------------------------------------------
    # We restrict the maximum total violation deduction per row evaluation to 30.
    # This ensures a device doesn't hit 0 from 100 on a single row tick if it breaks 
    # multiple rules concurrently, allowing the trust score to decay visibly over time 
    # rather than failing instantaneously.
    penalty = min(penalty, 30)

    return penalty, reasons

def get_policy_limits():
    """
    Utility exposure function that returns the deeply internal hardcoded limits
    outwards so the frontend Jinja templates and API endpoints can properly render 
    dynamic visual guidelines and threshold marker lines on charts based on these exact values.
    """
    return {
        'approved_ports': APPROVED_PORTS,
        'approved_ip_prefixes': APPROVED_IP_PREFIXES,
        'max_failed_connections': MAX_FAILED_CONNECTIONS,
        'hard_traffic_cap': HARD_TRAFFIC_CAP
    }