# =============================================================================
# DATABASE MODULE — TrustSphere
# =============================================================================
# This module handles the setup, initialization, and connection pooling for the 
# local SQLite database used by TrustSphere. It defines the core schema required
# to store device profiles, raw telemetry, and temporal trust history.
# =============================================================================

import sqlite3
import os
import logging
from config import DATABASE_URI  # type: ignore

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

class CursorWrapper:
    """
    Intelligent cursor wrapper that dynamically translates SQLite syntaxes 
    (like ? placeholders and AUTOINCREMENT) into PostgreSQL-compatible syntax 
    on the fly. This avoids having to rewrite hundreds of lines of legacy code in app.py.
    """
    def __init__(self, cursor, is_postgres):
        self.cursor = cursor
        self.is_postgres = is_postgres

    def execute(self, query, params=None):
        if self.is_postgres:
            # Dynamically cast DB engines
            query = query.replace('?', '%s')
            query = query.replace('AUTOINCREMENT', 'SERIAL')
            
        if params:
            self.cursor.execute(query, params)
        else:
            self.cursor.execute(query)
            
    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()
        
    def close(self):
        self.cursor.close()

class ConnectionWrapper:
    def __init__(self, conn, is_postgres):
        self.conn = conn
        self.is_postgres = is_postgres
        
    def cursor(self):
        return CursorWrapper(self.conn.cursor(), self.is_postgres)
        
    def commit(self):
        self.conn.commit()
        
    def close(self):
        self.conn.close()

def get_connection():
    """
    Establishes and returns a new active connection to either Postgres or SQLite.
    """
    if DATABASE_URI.startswith('postgres'):
        if not psycopg2:
            raise RuntimeError("psycopg2-binary is required for PostgreSQL. Please install it.")
        # We use RealDictCursor to perfectly mimic sqlite3.Row functionality
        conn = psycopg2.connect(DATABASE_URI, cursor_factory=RealDictCursor)
        return ConnectionWrapper(conn, True)
    else:
        # Parse sqlite path gracefully 
        path = DATABASE_URI.replace('sqlite:///', '')
        if not path or path == 'trustsphere.db':
            path = os.path.join(os.path.dirname(__file__), '..', 'trustsphere.db')
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return ConnectionWrapper(conn, False)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # 1: Devices Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            trust_score REAL DEFAULT 100,
            previous_score REAL DEFAULT NULL,
            baseline_packets REAL DEFAULT NULL,
            baseline_failed REAL DEFAULT NULL,
            baseline_unique_ips REAL DEFAULT NULL,
            drift_streak INTEGER DEFAULT 0,
            confirmation_days INTEGER DEFAULT 0,
            last_updated TEXT,
            mode TEXT DEFAULT 'NORMAL'
        )
    ''')

    # 2: Telemetry Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            timestamp TEXT,
            packets_per_min REAL,
            port_used INTEGER,
            destination_ip TEXT,
            failed_connections INTEGER
        )
    ''')

    # 3: Trust History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS trust_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            timestamp TEXT,
            trust_score REAL,
            severity TEXT,
            explanation TEXT
        )
    ''')
    
    # 4. Users table (Phase 2 Authenticiation addition)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # MIGRATION SAFETY BLOCK for SQLite local users dynamically running old code
    if not conn.is_postgres:
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN mode TEXT DEFAULT 'NORMAL'")
        except sqlite3.OperationalError:
            pass 

    conn.commit()
    conn.close()