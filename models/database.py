# =============================================================================
# DATABASE MODULE — TrustSphere
# =============================================================================
# This module handles the setup, initialization, and connection pooling for the 
# local SQLite database used by TrustSphere. It defines the core schema required
# to store device profiles, raw telemetry, and temporal trust history.
# =============================================================================

import sqlite3
import os

# DB_PATH: Computes the absolute file path where the SQLite database file 
# will be physically stored or created. It points to the parent directory 
# of this 'models' folder, naming the file 'trustsphere.db'.
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'trustsphere.db')

def get_connection():
    """
    Establishes and returns a new active connection to the SQLite database.
    Configures the connection to use sqlite3.Row, allowing rows to be 
    accessed natively as dictionary-like objects (e.g., row['device_id']) 
    rather than purely integer-indexed tuples (e.g., row[0]).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the deterministic schema of the database on application startup.
    Uses 'CREATE TABLE IF NOT EXISTS' to ensure absolute safety and idempotency, 
    meaning this function can be run multiple times safely without wiping existing data.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # -------------------------------------------------------------------------
    # TABLE 1: devices
    # -------------------------------------------------------------------------
    # Acts as the master registry mapping each known IoT device ID to its current 
    # persistent state, computed baseline metrics, and current trust profile.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            trust_score REAL DEFAULT 100,           -- The current active trust score
            previous_score REAL DEFAULT NULL,       -- The score immediately prior to the latest computation phase 
            baseline_packets REAL DEFAULT NULL,     -- The learned normal packet volume per minute
            baseline_failed REAL DEFAULT NULL,      -- The learned normal failed connection volume
            baseline_unique_ips REAL DEFAULT NULL,  -- The learned normal count of unique destination IPs spoken to
            drift_streak INTEGER DEFAULT 0,         -- Counter tracking consecutive chronological units of detected drift
            confirmation_days INTEGER DEFAULT 0,    -- Counter tracking observation cycles for baseline auto-adjustment
            last_updated TEXT,                      -- ISO timestamp of the last state mutation
            mode TEXT DEFAULT 'NORMAL'              -- The current behavioral categorization state machine phase
        )
    ''')

    # -------------------------------------------------------------------------
    # TABLE 2: telemetry
    # -------------------------------------------------------------------------
    # An append-only ledger storing every single raw packet/row of information 
    # uploaded via CSV. Useful for data retention, human auditing, and re-processing.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            timestamp TEXT,                         -- The explicit chronological time of the event
            packets_per_min REAL,                   -- Volume metric
            port_used INTEGER,                      -- Networking configuration metric
            destination_ip TEXT,                    -- Target address metric
            failed_connections INTEGER              -- Error/brute-force signaling metric
        )
    ''')

    # -------------------------------------------------------------------------
    # TABLE 3: trust_history
    # -------------------------------------------------------------------------
    # A temporal tracking ledger that logs point-in-time trust score variations 
    # and the massive JSON explanation payload dictating exactly WHY the score changed.
    # Entirely powers the dashboard timeline graph and explainability deep links.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS trust_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,                         -- The specific device being scored
            timestamp TEXT,                         -- The exact moment the evaluation happened
            trust_score REAL,                       -- The generated score output
            severity TEXT,                          -- Human-readable categorization string (e.g., CRITICAL, GOOD)
            explanation TEXT                        -- Highly detailed JSON payload containing generation logic
        )
    ''')

    # -------------------------------------------------------------------------
    # MIGRATION SAFETY BLOCK
    # -------------------------------------------------------------------------
    # Gracefully attempts to append the 'mode' column if an older version of the 
    # SQLite schema is actively running on the local machine during startup.
    # Exception handling catches and swallows the OperationalError if it already exists.
    try:
        cursor.execute("ALTER TABLE devices ADD COLUMN mode TEXT DEFAULT 'NORMAL'")
    except sqlite3.OperationalError:
        pass # Column already structurally exists; bypass safely

    # Finalize writes and sever connection mathematically to free locks
    conn.commit()
    conn.close()