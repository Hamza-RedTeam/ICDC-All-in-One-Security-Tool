import sqlite3
from core.config_loader import CONFIG

DB_URL = CONFIG.get("program", "db_url", default="sqlite:///icdc_program.db")
DB_PATH = DB_URL.replace("sqlite:///", "")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, workstream TEXT, module TEXT,
            severity TEXT, message TEXT, data TEXT
        );
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY, hostname TEXT, ip TEXT,
            os TEXT, critical INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, source TEXT, asset TEXT, severity TEXT,
            title TEXT, status TEXT DEFAULT 'open'
        );
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, name TEXT, value REAL
        );
        CREATE TABLE IF NOT EXISTS compliance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, framework TEXT, control TEXT, status TEXT
        );
    """)
    conn.commit()
    conn.close()

def log_event(workstream, module, severity, message, data=None):
    import json, datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO events (ts, workstream, module, severity, message, data) VALUES (?,?,?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), workstream, module,
         severity, message, json.dumps(data or {}))
    )
    conn.commit(); conn.close()

def log_metric(name, value):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO metrics (ts, name, value) VALUES (?,?,?)",
                 (datetime.datetime.utcnow().isoformat(), name, float(value)))
    conn.commit(); conn.close()

def log_finding(source, asset, severity, title):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO findings (ts, source, asset, severity, title) VALUES (?,?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), source, asset, severity, title)
    )
    conn.commit(); conn.close()

def log_compliance(framework, control, status):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO compliance (ts, framework, control, status) VALUES (?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), framework, control, status)
    )
    conn.commit(); conn.close()
