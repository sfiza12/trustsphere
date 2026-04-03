# =============================================================================
# EXPLAINABILITY GENERATION ENGINE — TrustSphere
# =============================================================================
# This synthesis engine acts as the translation layer between the raw mathematics 
# of the detection engines and the human-readable dashboard. 
# 
# It ingests every signal, penalty, state string, and calculation generated across 
# all engines during a single telemetry row evaluation, and compiles them into a 
# comprehensive JSON-compatible dictionary payload. This payload explains explicitly 
# WHY a device's score mutated in the exact manner it did.
# =============================================================================

def generate_explanation(
    device_id,
    trust_score,
    severity,
    hard_penalty,
    drift_penalty,
    ml_penalty,
    ml_score,
    hard_reasons,
    drift_reasons,
    drift_type,
    current_packets,
    baseline_packets,
    destination_ip=None,
    port_used=None,
    score_before=None
):
    """
    Generates the complete structured JSON payload detailing a device's point-in-time state.
    
    Args:
        device_id (str): Focus device.
        trust_score (float): The final mathematically calculated score post-tick.
        severity (str): The categorical severity assignment.
        hard_penalty (int): Deduction applied by Policy rules.
        drift_penalty (int): Deduction applied by statistical drift.
        ml_penalty (int): Deduction applied by Anomaly model.
        ml_score (float): Raw anomaly scalar from Isolation Forest (0.0 to 1.0).
        hard_reasons (list): Array of human strings detailing exactly which policy broke.
        drift_reasons (list): Array of human strings detailing exact drift deviations.
        drift_type (str): Categorical flag ('spike', 'sustained', 'early', 'none').
        current_packets (float): Volume acting within this slice.
        baseline_packets (float): Historical norm logic comparing against.
        destination_ip (str, optional): Target IP for Threat Intel checking.
        port_used (int, optional): Port parameter focus.
        score_before (float, optional): Snapshotted score prior to these applications.
        
    Returns:
        dict: The massive nested dictionary representing the explanation object.
              Serialized directly into the 'trust_history' sqlite tracking table.
    """
    
    explanation = {}
    
    # -------------------------------------------------------------------------
    # IDENTITY & CORE METADATA
    # -------------------------------------------------------------------------
    explanation['device_id'] = device_id
    explanation['trust_score'] = trust_score
    explanation['severity'] = severity
    
    # score_before preserves explicit timeline causality logic.
    # It allows the UI frontend to render mathematically correct deduction equations 
    # e.g., max(0, 55 - 45) = 10, instead of confusing a user by rendering max(0, 100 - 45) = 10.
    explanation['score_before'] = score_before if score_before is not None else trust_score
    
    # -------------------------------------------------------------------------
    # HIGH LEVEL EXECUTIVE SUMMARY
    # -------------------------------------------------------------------------
    # Generates a single plain-English sentence summarizing the entire macro state.
    if severity == "Trusted":
        explanation['summary'] = (
            f"Device {device_id} is operating securely within established behavioral parameters. "
            f"No significant policy violations, mechanical deviations, or drift detected."
        )
    elif severity in ["Low Risk", "Medium Risk"]:
        explanation['summary'] = (
            f"Device {device_id} is exhibiting mild to moderate behavioral anomalies. "
            f"Continued monitoring is recommended as drift patterns establish."
        )
    else:
        explanation['summary'] = (
            f"Device {device_id} has exhibited highly significant, mathematically proven behavioral deviations. "
            f"Immediate human investigation or automated playbook detonation is recommended."
        )
    
    # -------------------------------------------------------------------------
    # RAW LOGICAL ENGINE OUTPUTS
    # -------------------------------------------------------------------------
    explanation['hard_violations'] = hard_reasons if hard_reasons else ["No policy violations detected."]
    explanation['drift_signals'] = drift_reasons if drift_reasons else ["No behavioral drift detected."]
    
    # -------------------------------------------------------------------------
    # THREAT INTELLIGENCE CROSS-REFERENCING (MOCK LAYER)
    # -------------------------------------------------------------------------
    # Simulates an integration with an external enterprise Threat Feeds API (like CrowdStrike or OTX).
    KNOWN_THREATS = {
        '185.99.12.34': 'Known Mirai Botnet Command & Control (C2) Server. Associated with IoT DDoS campaigns.',
        '185.23.45.11': 'Suspected Data Exfiltration Drop Node. Tracked by global cyber threat alliances.'
    }
    
    if destination_ip in KNOWN_THREATS:
        explanation['threat_intel'] = f"CRITICAL MATCH: Destination IP {destination_ip} is flagged in our global threat feeds. {KNOWN_THREATS[destination_ip]}"
    else:
        explanation['threat_intel'] = "No known threat signatures matched for current destination IP within our global index."
    
    # -------------------------------------------------------------------------
    # MACHINE LEARNING LINGUISTIC INTERPRETATION
    # -------------------------------------------------------------------------
    # Translates the opaque 0.0-1.0 ML float score into a comprehensible reasoning.
    if ml_score > 0.7:
        explanation['ml_interpretation'] = (
            f"The ML anomaly model (Unsupervised Isolation Forest) assigned a critical severity score of "
            f"{ml_score:.2f} out of 1.0. This structurally indicates a high probability "
            f"that the device's combined multi-dimensional behavioral pattern is statistically "
            f"extremely unusual compared to historically observed norms."
        )
    elif ml_score > 0.5:
        explanation['ml_interpretation'] = (
            f"The ML model detected a moderate multi-axis anomaly (score: {ml_score:.2f}/1.0). "
            f"The behavioral payload combination points to some unusual, uncharacteristic routing characteristics."
        )
    else:
        explanation['ml_interpretation'] = (
            f"ML model score: {ml_score:.2f}/1.0. "
            f"No significant structural pattern anomalies detected by multidimensional ML assessment."
        )

    # -------------------------------------------------------------------------
    # AUTOMATED REMEDIATION PLAYBOOKS (ENTERPRISE ACTION LAYER)
    # -------------------------------------------------------------------------
    # Based on the exact mathematical categorization of the issue, dynamically recommends 
    # or simulates explicit security actions equivalent to a SIEM/SOAR integration.
    playbooks = []
    
    if hard_penalty > 0:
        # Action specifically mapped to unauthorized networking layer ports
        if port_used and port_used not in [80, 443, 8080, 22, 21]:
            playbooks.append(f"🔌 IMMEDIATE ACTION: Issue automated switch-level physical port shutdown for unauthorized port {port_used}.")
        # Action specifically mapped to Threat Intel malicious addresses
        if destination_ip and any(str(destination_ip).startswith(p) for p in ['185.99.', '185.23.']):
            playbooks.append(f"🛡️ IMMEDIATE ACTION: Push dynamic Next-Gen Firewall rule to aggressively block malicious IP {destination_ip}.")
            
    if drift_penalty > 0:
        # Different actions based on if the drift is an absolute spike or a slow burn.
        if drift_type == "sustained":
            playbooks.append("📈 INVESTIGATION: Isolate physical device to Quarantine/Scrubbing VLAN for deep behavioral review. Sustained drift established.")
        elif drift_type == "spike":
            playbooks.append("📈 MONITORING: Flag device specifically for deep-packet inspection (DPI) processing tier due to sudden volumetric traffic spike.")
            
    if ml_score > 0.7:
        # ML represents highly complex credential/botnet hijacking usually
        playbooks.append("🤖 ML REMEDIATION: Automated revocation of authentication API keys/tokens recommended. Highly anomalous multi-feature behavior detected.")

    # Failsafe default playbook
    if not playbooks:
        playbooks.append("✅ ALL CLEAR: No action required. Device operating strictly within expected behavioral confidence bands.")
        
    explanation['remediation_playbooks'] = playbooks

    # -------------------------------------------------------------------------
    # FINAL METRIC EXPORT PACKAGING
    # -------------------------------------------------------------------------
    # Breaks down the aggregate trust score penalty pie chart components mathematically
    explanation['risk_breakdown'] = {
        'hard_violation_penalty': hard_penalty,
        'drift_penalty': drift_penalty,
        'ml_anomaly_penalty': ml_penalty,
        'total_penalty': hard_penalty + drift_penalty + ml_penalty
    }
    
    explanation['severity_reasoning'] = (
        f"A calculated Trust Score of {trust_score} mathematically falls directly into the '{severity}' category "
        f"(Definitions: 80-100: Trusted, 60-79: Low Risk, 40-59: Medium Risk, "
        f"20-39: High Risk, 0-19: Critical)."
    )
    
    # Appends the raw numerical deviation for transparency
    if baseline_packets and baseline_packets > 0:
        drift_pct = ((current_packets - baseline_packets) / baseline_packets) * 100
        explanation['traffic_context'] = (
            f"Current active traffic block: {current_packets:.0f} packets/min. "
            f"Established historical baseline: {baseline_packets:.0f} packets/min. "
            f"Mathematical Deviation: {drift_pct:+.1f}%."
        )
    else:
        explanation['traffic_context'] = (
            f"Current active traffic block: {current_packets:.0f} packets/min. "
            f"Baseline norms not yet established statistically."
        )
    
    return explanation