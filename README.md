# TrustSphere 🛡️
### IoT Behavioral Trust Analytics Platform



TrustSphere monitors IoT devices and assigns each a dynamic trust score (0-100) 
based on behavioral analysis. It detects policy violations, behavioral drift, 
and multi-parameter anomalies in real time.

---

## What It Does

- Scores every IoT device dynamically — 0 to 100
- Detects hard policy violations immediately
- Catches gradual behavioral drift over time
- Uses ML to detect subtle multi-parameter anomalies
- Explains every decision in plain English

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask |
| Database | SQLite |
| ML | scikit-learn, Isolation Forest |
| Frontend | HTML, CSS, JavaScript |

---

## How To Run
```bash
# Clone the repo
git clone https://github.com/YOURUSERNAME/trustsphere.git
cd trustsphere

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Open browser at `http://127.0.0.1:5000`

---

## Project Status
🚧 Work in progress — converting hackathon prototype to full project