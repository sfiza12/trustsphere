---

# 🛡️ TrustSphere
### IoT Behavioral Trust Analytics Platform



TrustSphere is a real-time IoT security platform that monitors 
device behavior and assigns each device a dynamic trust score 
from 0 to 100. It detects policy violations, behavioral drift, 
and subtle multi-parameter anomalies using machine learning.

---

## ✨ Key Features

- **Dynamic Trust Scoring** — Every device scored 0-100, updated every hour
- **Hard Violation Detection** — Immediate flagging of unauthorized ports, IPs, excessive failures
- **Behavioral Drift Detection** — Detects gradual traffic changes over 6 consecutive hours
- **ML Anomaly Detection** — Isolation Forest catches multi-parameter anomalies rules miss
- **Baseline Adaptation** — Anti-poisoning gated baseline updates
- **Live MQTT Streaming** — Real-time telemetry via MQTT broker
- **CSV Upload** — Batch telemetry upload for testing and demo
- **Authentication** — Secure login with bcrypt password hashing
- **Full Explainability** — Every score decision explained in plain English

---

## 🏗️ Architecture
IoT Devices / MQTT Publisher
↓
HiveMQ Broker
↓
mqtt_listener.py (background thread)
↓                              ↑
/api/upload (CSV)                   |
↓                              |
process_telemetry()                 |
↓                              |
┌─────────────────────────────┐     |
│  Hard Violation Engine      │     |
│  Drift Detection Engine     │     |
│  ML Anomaly Module          │     |
│  Trust Score Engine         │     |
│  Explainability Engine      │     |
│  Baseline Manager           │     |
└─────────────────────────────┘     |
↓                              |
SQLite Database                     |
↓                              |
REST API → Dashboard ───────────────┘

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Database | SQLite (PostgreSQL ready) |
| ML | scikit-learn — Isolation Forest |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Messaging | MQTT via HiveMQ |
| Auth | Flask-Login + bcrypt |
| Config | YAML based central config |

---

## 🚀 Quick Start

### 1. Clone and install
```bash
git clone https://github.com/sfiza12/trustsphere.git
cd trustsphere
python -m venv venv
venv\Scripts\activate       # Windows
source venv/bin/activate    # Mac/Linux
pip install -r requirements.txt
```

### 2. Run the app
```bash
python app.py
```
Open browser at `http://127.0.0.1:5000`

### 3. Register and login
Create an account at `/register` then login at `/login`

### 4. Feed data — Option A: CSV Upload
Go to Upload page and upload any CSV from the `data/` folder.
Stage files: `stage1.csv` → `stage2.csv` → `stage3.csv` → `stage4.csv`

### 5. Feed data — Option B: Live MQTT Demo
In a second terminal:
```bash
python scripts/demo_publisher.py
```
Watch the dashboard update automatically every 5 seconds.

---

## 📁 Project Structure
trustsphere/
├── app.py                  # Main Flask app and processing pipeline
├── config.py               # Config loader
├── config.yaml             # All thresholds and constants
├── requirements.txt
├── models/
│   ├── auth.py             # User authentication
│   ├── baseline_manager.py # Anti-poisoning baseline adaptation
│   ├── database.py         # SQLite connection and schema
│   ├── drift_engine.py     # Behavioral drift detection
│   ├── explainability.py   # Human-readable explanations
│   ├── ml_module.py        # Isolation Forest anomaly detection
│   ├── mqtt_listener.py    # Live MQTT telemetry receiver
│   ├── trust_score.py      # Trust score aggregation
│   └── violation_engine.py # Hard policy violation checks
├── templates/
│   ├── index.html          # Main dashboard
│   ├── device.html         # Device detail page
│   ├── login.html          # Login page
│   ├── register.html       # Register page
│   └── upload.html         # CSV upload page
├── scripts/
│   └── demo_publisher.py   # MQTT demo simulation script
├── data/
│   ├── stage1.csv          # Demo telemetry — hours 0-5
│   ├── stage2.csv          # Demo telemetry — hours 6-11
│   ├── stage3.csv          # Demo telemetry — hours 12-17
│   └── stage4.csv          # Demo telemetry — hours 18-23
└── static/
└── .gitkeep

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | All devices with current trust scores |
| GET | `/api/device/<id>` | Single device full details and history |
| GET | `/api/explain/<id>` | Full explainability breakdown |
| POST | `/api/upload` | Upload CSV telemetry file |
| POST | `/api/reset` | Clear all data (admin/demo use) |

---

## 🔧 Configuration

All thresholds live in `config.yaml` — no hardcoded values:

```yaml
drift_threshold: 0.30        # 30% deviation triggers drift detection
spike_threshold: 0.50        # 50% deviation triggers immediate spike
sustained_hours: 6           # Consecutive hours to confirm sustained drift
confirmation_hours_required: 6
ml_threshold: 0.75
recovery_per_clean_hour: 5
```

---

## 📊 Demo Devices

| Device | Baseline | Story |
|--------|----------|-------|
| SENSOR_01 | 20 pkt/min | Stable all day — no anomalies |
| THERMOSTAT_02 | 50 pkt/min | Legitimate drift → baseline adapts → recovers |
| CAM_03 | 100 pkt/min | Stable all day — no anomalies |
| BULB_04 | 5 pkt/min | ML catches subtle multi-parameter anomaly |
| ROUTER_05 | 150 pkt/min | Hard violation — Mirai botnet port + IP |

---

## 🚧 Roadmap

- [ ] PostgreSQL support for production
- [ ] Deploy to Render/Railway
- [ ] Unit tests for each engine
- [ ] API rate limiting
- [ ] Email alerts on Critical score

---