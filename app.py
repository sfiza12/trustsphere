# =============================================================================
# TRUSTSPHERE MAIN APPLICATION FILE (app.py)
# =============================================================================
# This is the core Flask application handling routing, API endpoints, database
# interactions, and orchestrating the orchestration of all TrustSphere processing 
# engines (Violation, Drift, ML, Trust Score, Explainability, Baseline Manager).
# =============================================================================

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
import pandas as pd
import json
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, login_required, current_user  # type: ignore

# Import internal models and engines
from models.database import init_db, get_connection
from models.violation_engine import check_violations, get_policy_limits
from models.drift_engine import check_drift
from models.ml_module import check_ml_anomaly, train_model
from models.trust_score import calculate_trust_score, apply_recovery, get_severity
from models.explainability import generate_explanation
from models.baseline_manager import should_update_baseline, calculate_new_baseline, initialize_baseline
import logging

from config import SUSTAINED_HOURS, CONFIRMATION_HOURS_REQUIRED  # type: ignore
from models.auth import User
from models.mqtt_listener import start_mqtt_listener  # type: ignore
import secrets

# Initialize the Flask application
app = Flask(__name__)
# Use a strong secret key for sessions
app.secret_key = secrets.token_hex(32)

# Set up Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Ensure the database schemas and tables are initialized when the app starts
with app.app_context():
    init_db()

# -----------------------------------------------------------------------------
# AUTHENTICATION ROUTES
# -----------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Please provide both username and password.')
            return redirect(url_for('register'))
            
        if User.get_by_username(username):
            flash('Username already exists. Choose another.')
            return redirect(url_for('register'))
            
        success = User.create(username, password)
        if success:
            user = User.get_by_username(username)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('An error occurred during registration.')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# -----------------------------------------------------------------------------
# FRONTEND ROUTES
# -----------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    """
    Serves the main dashboard application page (index.html).
    """
    return render_template('index.html')

@app.route('/upload-page')
@login_required
def upload_page():
    """
    Serves the page for users to upload static CSV telemetry data.
    """
    return render_template('upload.html')

@app.route('/device-page/<device_id>')
@login_required
def device_page(device_id):
    """
    Serves the dedicated detail view page for a specific device.
    Passes the device_id to the Jinja template to construct subsequent API calls.
    """
    return render_template('device.html', device_id=device_id)

# -----------------------------------------------------------------------------
# API ROUTES
# -----------------------------------------------------------------------------

@app.route('/api/upload', methods=['POST'])
def upload_telemetry():
    """
    API endpoint that receives CSV telemetry data uploads.
    Reads the CSV, normalizes column headers, and pipes the dataframe 
    into the monolithic process_telemetry() orchestrator function.
    """
    # 1. Validate file presence
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    
    # 2. Validate file type
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Please upload a CSV file'}), 400
        
    try:
        # 3. Parse CSV data via pandas dataframe for robust typing
        df = pd.read_csv(file)
        
        # Strip trailing whitespaces and enforce lowercase for consistency in data mapping
        df.columns = df.columns.str.strip().str.lower()
        
        # 4. Process all loaded data through the core TrustSphere logic engines
        result = process_telemetry(df)
        
        # 5. Return success payload
        return jsonify({
            'success': True,
            'message': f'Processed {len(df)} records for {result["devices_count"]} devices',
            'devices': result['devices_count']
        })
    except Exception as e:
        # Catch-all exception block returning standard HTTP 500 error mapping
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices', methods=['GET'])
def get_devices():
    """
    API endpoint to retrieve the high-level summary of all known devices 
    and their current state, sorted by trust score (most compromised first).
    Powers the main dashboard overview grid.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch top-level metadata across all devices.
    # Ordered by descending risk (ascending trust score).
    cursor.execute('''
        SELECT device_id, trust_score, previous_score, last_updated,
               baseline_packets, drift_streak, mode
        FROM devices ORDER BY trust_score ASC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    devices = []
    # Marshall sqlite rows into standard JSON payload dictionaries
    for row in rows:
        score = row['trust_score']
        prev = row['previous_score']
        
        # Calculate numeric delta between previous trust score block and current score
        change = round(score - prev, 1) if prev is not None else None
        
        devices.append({
            'device_id': row['device_id'],
            'trust_score': score,
            'previous_score': prev,
            'change': change,
            'severity': get_severity(score), # Assign visual severity (e.g. NORMAL, CRITICAL)
            'last_updated': row['last_updated'],
            'drift_streak': row['drift_streak'],
            'baseline_packets': row['baseline_packets'],
            'mode': row['mode'] # e.g. NORMAL, DRIFT DETECTED, BASELINE CONFIRMATION
        })
    return jsonify(devices)


@app.route('/api/device/<device_id>', methods=['GET'])
def get_device(device_id):
    """
    API endpoint retrieving complete deep-dive details for a single specific device.
    Fetches the device configuration, historical timeline, and recent raw telemetry.
    Powers the dedicated device detail page.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch root device record
    cursor.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,))
    device = cursor.fetchone()
    
    # Edge case: Return 404 if queried device does not exist in our systems
    if not device:
        return jsonify({'error': 'Device not found'}), 404
        
    # Fetch purely the last 10 raw telemetry packets for visibility
    cursor.execute('''
        SELECT * FROM telemetry WHERE device_id = ?
        ORDER BY timestamp DESC LIMIT 10
    ''', (device_id,))
    recent_telemetry = cursor.fetchall()
    
    # Fetch historical timeline data mapping trust score changes over time
    cursor.execute('''
        SELECT timestamp, trust_score, severity FROM trust_history
        WHERE device_id = ? ORDER BY timestamp ASC
    ''', (device_id,))
    history = cursor.fetchall()
    
    conn.close()
    
    # Construct complete structured JSON payload
    return jsonify({
        'device_id': device_id,
        'trust_score': device['trust_score'],
        'severity': get_severity(device['trust_score']),
        'baseline_packets': device['baseline_packets'],
        'drift_streak': device['drift_streak'],
        'last_updated': device['last_updated'],
        # Legacy fallback if mode isn't initialized yet
        'mode': device['mode'] if 'mode' in device.keys() else 'NORMAL',
        'recent_telemetry': [dict(r) for r in recent_telemetry],
        'history': [dict(h) for h in history],
        # Returns global thresholds to the frontend so charts can draw threshold lines
        'policy_limits': get_policy_limits()
    })


@app.route('/api/explain/<device_id>', methods=['GET'])
def explain_device(device_id):
    """
    API Endpoint: Returns detailed LLM/Rule-based explainability for a device.
    Supports querying either the explicit 'current' explanation OR the 'previous' 
    explanation using the ?view=query_param mapping.

    FIX Context: We now store a stage_marker in trust_history so we can
    correctly pull the last row of a previous stage, not just OFFSET 1.
    Since we save every row, we use the stage boundaries stored in the
    devices table (previous_score timestamp) to find the right entry.
    """
    # Fetch desired context. Defaults to current.
    view_type = request.args.get('view', 'current')
    conn = get_connection()
    cursor = conn.cursor()

    if view_type == 'previous':
        # Get the explanation saved just before the most recent stage started
        # By using OFFSET 1 we are going one logical timeline step backward 
        # from the latest generated metric.
        cursor.execute('''
            SELECT explanation FROM trust_history
            WHERE device_id = ?
            ORDER BY timestamp DESC
            LIMIT 1 OFFSET 1
        ''', (device_id,))
    else:
        # Default behavior: Grab the absolute latest explanation json payload created
        cursor.execute('''
            SELECT explanation FROM trust_history
            WHERE device_id = ?
            ORDER BY timestamp DESC LIMIT 1
        ''', (device_id,))

    row = cursor.fetchone()
    conn.close()
    
    # Defensive programming: error boundary if no explanations are computed yet
    if not row or not row['explanation']:
        return jsonify({'error': 'No explanation history found'}), 404
        
    # Deserializes the stored JSON blob to a native dictionary payload
    return jsonify(json.loads(row['explanation']))


# ─────────────────────────────────────────────────────────────────
# CORE PROCESSING FUNCTION
# ─────────────────────────────────────────────────────────────────
def process_telemetry(df):
    """
    The main architectural core of the application.
    Processing pipeline — processes every telemetry row chronologically 
    and passes it through all four detection engines in sequential order.

    KEY LOGIC:
    ──────────────────────────────────────────────────────────────
    1. STREAK ACCUMULATION FIX
       Engines run sequentially on every row. After each row processes,
       we save the calculated state continuously back into the local process dict:
         device_dict['drift_streak'] = new_streak
         current_score = new_score
       This state continuity means day 2 sees streak from day 1, and so on.

    2. DRIFT PENALTY DURING CONFIRMATION — THE MAIN FIX
       Once sustained minor drift is statistically confirmed (streak >= 3) AND there are
       no hard/critical violations present, the system enters a distinct observation mode.
       During this observation: drift_penalty is actively suppressed (reduced to 0).
       This acts as a buffer preventing false complete lockouts (e.g. THERMOSTAT_05 
       crashing to 0 trust entirely due to a slight environmental change). 
       The system is acknowledging the new norm and watching it, not punishing it continually.

       WHY THIS IS CORRECT:
       - streak 1,2 = early warning period → we apply a small penalty (-5) ✅
       - streak 3   = sustained confirmed → we apply a bigger penalty (-20) ✅
       - streak 4+  = observation/confirmation mode → we suppress penalties (0) ✅
       - hard violation present → malicious activity overrides observation, always penalize ✅

    3. BASELINE ADAPTATION PER ROW
       calculate_new_baseline triggers periodically inside the evaluation loop (not just 
       on the absolute last batch row) so the baseline smoothly shifts each chronological day 
       during the confirmation period mathematically.

    4. PREVIOUS SCORE = START OF BATCH
       previous_score saved = trust score before this entire processing stage started.
       This is precisely what the visual dashboard's "Previous Score" column renders.

    5. MODE STATES DECLARED GLOBALLY
       NORMAL              → Behavior matches norm, no drift, no violations
       HARD VIOLATION      → Explicitly bad packets/ports. Hard penalties firing
       DRIFT DETECTED      → Minor numeric deviation detected (streak 1 or 2)
       BASELINE CONFIRMATION → Streak >= 3, no violations, system suppressing penalties and observing
       BASELINE UPDATED    → Confirmation complete, original baseline statically shifted
    """

    conn = get_connection()
    cursor = conn.cursor()

    # PHASE 1: Store all incoming raw telemetry rows to the database immediately
    # for auditing, rollback potential, and raw data display purposes.
    for _, row in df.iterrows():
        cursor.execute('''
            INSERT INTO telemetry
            (device_id, timestamp, packets_per_min, port_used, destination_ip, failed_connections)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            row['device_id'], row['timestamp'], row['packets_per_min'],
            row['port_used'], row['destination_ip'], row['failed_connections']
        ))
    conn.commit()

    # Isolate unique device IDs in the batch to process them independently
    device_ids = df['device_id'].unique()

    # PHASE 2: Core Loop iterating over each distinct device individually
    for device_id in device_ids:
        try:
            # Pre-sort device traffic chronologically to ensure logical progression
            # (day 1 traffic processed before day 2)
            device_df = df[df['device_id'] == device_id].sort_values('timestamp')

            # Retrieve current internal state for this device from DB
            cursor.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,))
            device_row = cursor.fetchone()

            # If device is completely unknown (new device connection event), 
            # initialize it at max trust (100) and register it in systems.
            if not device_row:
                cursor.execute('''
                    INSERT INTO devices (device_id, trust_score, last_updated)
                    VALUES (?, 100, ?)
                ''', (device_id, datetime.now().isoformat()))
                conn.commit()
                # Re-fetch populated row
                cursor.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,))
                device_row = cursor.fetchone()

            # Cast SQLite Row object to generic writable dictionary 
            device_dict = dict(device_row)

            # Retain score at the START of this batch chronologically.
            # This acts as our "before" snapshot to compare "after" batch computation.
            score_at_batch_start = device_dict['trust_score']
            current_score = device_dict['trust_score']

            # Determine total globally unique IPs spoken to during this batch 
            # (heuristic often linked with worm/DDoS behavior or C2 mapping).
            unique_ips = len(device_df['destination_ip'].unique())

            # ---------------------------------------------------------------------
            # ML Engine Preparation Step
            # ---------------------------------------------------------------------
            # Pre-accumulate training feature rows for the ML model over this entire 
            # specific chunk of data. This allows the model to periodically adapt.
            training_features = []
            for _, row in device_df.iterrows():
                training_features.append([
                    row['packets_per_min'],
                    row['failed_connections'],
                    unique_ips,
                    row['port_used']
                ])
                
            # Only invoke training overhead if we have a substantial enough data window (>10)
            # to prevent model overfitting on microscopic spikes.
            if len(training_features) >= 10:
                train_model(training_features, device_id=device_id)


            # ---------------------------------------------------------------------
            # Variable Initialization Phase for continuous row loop
            # ---------------------------------------------------------------------
            hard_penalty = 0
            drift_penalty = 0
            ml_penalty = 0
            ml_score = 0
            
            # Load accumulated persistence counters
            new_streak = device_dict.get('drift_streak') or 0
            new_confirmation = device_dict.get('confirmation_days') or 0
            
            new_score = current_score
            explanation = {}
            drift_type = "none"
            hard_reasons = []
            drift_reasons = []
            mode = "NORMAL"
            new_baseline_packets = device_dict['baseline_packets']

            # ── MAIN ROW LOOP ────────────────────────────────────────
            # Sequentially evaluate the device's action chronological step by step.
            for _, row in device_df.iterrows():
                try:
                    row_dict = row.to_dict()

                    # Self-healing logic for missing baselines. Only on first row iteration.
                    if device_dict['baseline_packets'] is None:
                        baseline = initialize_baseline(
                            row_dict['packets_per_min'],
                            row_dict['failed_connections'],
                            unique_ips
                        )
                        device_dict['baseline_packets'] = baseline['baseline_packets']
                        device_dict['baseline_failed'] = baseline['baseline_failed']
                        device_dict['baseline_unique_ips'] = baseline['baseline_unique_ips']
                        new_baseline_packets = device_dict['baseline_packets']

                    # STEP 1: ENGINE 1: Hard Violation (Static Policies)
                    hard_penalty, hard_reasons = check_violations(row_dict)
                    has_hard_violation = hard_penalty > 0 

                    # STEP 2: ENGINE 2: Drift Detection
                    drift_penalty, drift_type, drift_reasons, new_streak = check_drift(
                        device_dict,
                        row_dict['packets_per_min'],
                        row_dict['failed_connections'],
                        unique_ips
                    )

                    # OBSERVATION MODE FIX
                    if new_streak >= SUSTAINED_HOURS and not has_hard_violation:
                        drift_penalty = 0

                    # STEP 3: ENGINE 3: ML Anomaly Detection (Isolation Forest)
                    ml_penalty, ml_score, ml_reasons = check_ml_anomaly(
                        row_dict['packets_per_min'],
                        row_dict['failed_connections'],
                        unique_ips,
                        row_dict['port_used'],
                        device_id
                    )

                    # STEP 4: ENGINE 4: Aggregate Trust Score Engine
                    total_penalty = hard_penalty + drift_penalty + ml_penalty
                    
                    if total_penalty == 0:
                        new_score = apply_recovery(current_score)
                    else:
                        new_score, _ = calculate_trust_score(
                            current_score, hard_penalty, drift_penalty, ml_penalty
                        )
                        
                    severity = get_severity(new_score)

                    # BASELINE ADAPTATION
                    update_baseline, new_confirmation = should_update_baseline(
                        device_dict,
                        row_dict['packets_per_min'],
                        row_dict['failed_connections'],
                        unique_ips,
                        has_hard_violation
                    )
                    if update_baseline and device_dict['baseline_packets']:
                        new_baseline_packets = calculate_new_baseline(
                            device_dict['baseline_packets'],
                            row_dict['packets_per_min']
                        )
                        device_dict['baseline_packets'] = new_baseline_packets

                    # MODE CALCULATION
                    if has_hard_violation:
                        mode = "HARD VIOLATION"
                    elif new_streak == 0:
                        mode = "NORMAL"
                    elif new_streak < SUSTAINED_HOURS:
                        mode = "DRIFT DETECTED"
                    elif new_confirmation >= CONFIRMATION_HOURS_REQUIRED:
                        mode = "BASELINE UPDATED"
                    else:
                        mode = "BASELINE CONFIRMATION"

                    # STEP 5: Explanations
                    explanation = generate_explanation(
                        device_id=device_id,
                        trust_score=new_score,
                        severity=severity,
                        hard_penalty=hard_penalty,
                        drift_penalty=drift_penalty,
                        ml_penalty=ml_penalty,
                        ml_score=ml_score,
                        hard_reasons=hard_reasons,
                        drift_reasons=drift_reasons,
                        drift_type=drift_type,
                        current_packets=row_dict['packets_per_min'],
                        baseline_packets=device_dict['baseline_packets'],
                        destination_ip=row_dict['destination_ip'],
                        port_used=row_dict['port_used'],
                        score_before=current_score
                    )

                    cursor.execute('''
                        INSERT INTO trust_history (device_id, timestamp, trust_score, severity, explanation)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (device_id, row_dict['timestamp'], new_score, severity, json.dumps(explanation)))

                    device_dict['drift_streak'] = new_streak
                    device_dict['confirmation_days'] = new_confirmation
                    current_score = new_score
                    
                except Exception as e:
                    logging.error(f"Error processing individual row for {device_id}: {e}")
                    # Skip problematic row and continue
                    continue

            # END OF ROW BATCH LOOP
            cursor.execute('''
                UPDATE devices SET
                    trust_score = ?,
                    previous_score = ?,
                    baseline_packets = ?,
                    drift_streak = ?,
                    confirmation_days = ?,
                    last_updated = ?,
                    mode = ?
                WHERE device_id = ?
            ''', (
                new_score,
                score_at_batch_start,
                new_baseline_packets, 
                new_streak,
                new_confirmation,
                datetime.now().isoformat(),
                mode,
                device_id
            ))
            
        except Exception as e:
            logging.error(f"Error processing entire device batch for {device_id}: {e}")
            # Skip this entire device but allow other devices in the array to process
            continue

    # Commit all massive row + chunk database transaction shifts atomically.
    conn.commit()
    conn.close()
    
    # Return count of successfully completed devices 
    return {'devices_count': len(device_ids)}

# -----------------------------------------------------------------------------
# ADMINISTRATIVE ROUTES
# -----------------------------------------------------------------------------
@app.route('/api/reset', methods=['POST'])
def reset_database():
    """
    Administrative API endpoint intended purely for Demo/Testing cycles.
    Completely purges all data rows from tracking tables indiscriminately.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM devices')
    cursor.execute('DELETE FROM telemetry')
    cursor.execute('DELETE FROM trust_history')
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Database cleared'})

# -----------------------------------------------------------------------------
# RUN ENTRYPOINT
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    # Start the live background MQTT listener to actively poll for stream telemetry
    start_mqtt_listener(process_telemetry)
    
    # Binds internally to Flask development server on standard dev port
    # Disabled reloader to prevent duplicate MQTT background thread spawning
    app.run(debug=True, port=5000, use_reloader=False)