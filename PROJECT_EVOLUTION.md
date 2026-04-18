# 🛡️ TrustSphere - Project Evolution Summary

This document outlines the major features, architectural milestones, and logic enhancements implemented in TrustSphere so far.

## 🏗️ Phase 1: The Core Foundation
The initial build established the multi-engine orchestration pattern for IoT trust analytics.

- **Monolithic Orchestrator**: Developed `app.py` to handle data ingestion (CSV/MQTT) and pipe telemetry through sequential engines.
- **Violation Engine**: Implemented deterministic checks against hard security limits (e.g., packet bursts, unauthorized ports).
- **Statistical Drift Engine**: Built a z-score based engine to detect slow behavioral shifts compared to a statistical baseline.
- **Aggregated Trust Score**: Created a weighted scoring system (0-100) that computes penalties from multiple engines.

## 🧠 Phase 2: ML & Explainability
Transitioned from simple rules to adaptive intelligence and human-readable reasoning.

- **ML Anomaly Forest**: Integrated Scikit-Learn's `IsolationForest` to build dynamic behavioral profiles for every individual device.
- **Explainability Engine**: Developed a logic layer that translates raw numeric penalties into human-readable explanations (e.g., *"Trust dropped because failed connections spiked by 300%"*).
- **Historical Logic**: Modified the database to store `trust_history` and `explanations` for every telemetry batch, allowing for timeline visualization.

## 📡 Phase 3: Real-time Integration
Moved from static file processing to live network monitoring.

- **MQTT Listener**: Added a background thread that subscribes to IoT topics (HiveMQ) and processes packets in real-time.
- **Interactive Dashboards**: Built a frontend using Vanilla JS and CSS with:
    - Global device risk overview.
    - Real-time trust history charts.
    - Deep-dive device detail pages with raw telemetry views.

## 🔄 Phase 4: Device Lifecycle & Adaptive Baselines
Implemented a sophisticated state machine to handle environmental changes without false positives.

- **Baseline Manager**: Controls the transition between `NORMAL`, `DRIFT DETECTED`, `BASELINE CONFIRMATION`, and `BASELINE UPDATED` states.
- **Penalty Suppression**: Implemented logic to pause drift penalties during the "Confirmation Window," allowing the system to observe if a change is the "new normal" rather than an attack.
- **Dynamic Adaptation**: Enabled the system to mathematically shift the baseline once a new behavior pattern is confirmed over a sustained period (e.g., 3+ hours).

## 🛡️ Phase 5: Production Hardening
Refined the codebase for reliability, security, and professional presentation.

- **User Authentication**: Integrated `auth.py` and `flask-login` with secure password hashing and registration flows.
- **Multi-Database Support**: Configured the system to work with local `SQLite` for dev and `PostgreSQL` (e.g., Neon.tech) for production.
- **Deep Documentation**: Added comprehensive docstrings and comments to all core modules explaining the mathematical rationale behind engines.

---
*Status: Ready for feature extension or final hackathon polish.*
