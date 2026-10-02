import os
import sys
import json
import sqlite3
from datetime import datetime

def parse_zeek_log(filepath):
    """
    Parses a Zeek TSV log file, handling headers (#fields, #types) automatically.
    Returns field names and raw rows.
    """
    if not os.path.exists(filepath):
        return None, []
        
    fields = []
    rows = []
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                continue
            parts = line.split("\t")
            if len(parts) == len(fields):
                # Replace '-' (Zeek null value) with None
                row = [None if p == '-' else p for p in parts]
                rows.append(row)
    return fields, rows

def sanitize_column_name(name):
    return name.replace(".", "_")

def ingest_zeek_logs(db_cursor, zeek_dir):
    """
    Ingests common Zeek logs into SQLite.
    """
    log_files = {
        "conn.log": "zeek_conn",
        "dns.log": "zeek_dns",
        "http.log": "zeek_http"
    }
    
    for filename, tablename in log_files.items():
        filepath = os.path.join(zeek_dir, filename)
        if not os.path.exists(filepath):
            print(f"Skipping {filename}: not found.")
            continue
            
        fields, rows = parse_zeek_log(filepath)
        if not fields or not rows:
            print(f"No records found in {filename}.")
            continue
            
        # Create columns string (treating all as TEXT to be safe and simple)
        col_names = [sanitize_column_name(f) for f in fields]
        columns_def = ", ".join([f"{col} TEXT" for col in col_names])
        
        # Create Table
        db_cursor.execute(f"DROP TABLE IF EXISTS {tablename}")
        db_cursor.execute(f"CREATE TABLE {tablename} ({columns_def})")
        
        # Insert rows
        placeholders = ", ".join(["?"] * len(col_names))
        db_cursor.executemany(f"INSERT INTO {tablename} VALUES ({placeholders})", rows)
        print(f"Ingested {len(rows)} records into table '{tablename}' from {filename}.")

def ingest_suricata_alerts(db_cursor, suricata_eve_path):
    """
    Parses Suricata's eve.json and stores alert events in SQLite database.
    """
    if not os.path.exists(suricata_eve_path):
        print("Suricata eve.json not found, skipping alert ingestion.")
        return
        
    db_cursor.execute("DROP TABLE IF EXISTS suricata_alerts")
    db_cursor.execute("""
        CREATE TABLE suricata_alerts (
            timestamp TEXT,
            flow_id INTEGER,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            proto TEXT,
            signature TEXT,
            category TEXT,
            severity INTEGER
        )
    """)
    
    rows = []
    with open(suricata_eve_path, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alert = event.get("alert", {})
                    rows.append((
                        event.get("timestamp"),
                        event.get("flow_id"),
                        event.get("src_ip"),
                        event.get("src_port"),
                        event.get("dest_ip"),
                        event.get("dest_port"),
                        event.get("proto"),
                        alert.get("signature"),
                        alert.get("category"),
                        alert.get("severity")
                    ))
            except Exception as e:
                pass
                
    if rows:
        db_cursor.executemany("""
            INSERT INTO suricata_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        print(f"Ingested {len(rows)} alerts into table 'suricata_alerts'.")
    else:
        print("No alerts found in Suricata eve.json.")

def main():
    base_dir = "/workspace"
    capture_dir = os.path.join(base_dir, "capture")
    zeek_dir = os.path.join(capture_dir, "zeek_logs")
    suricata_eve = os.path.join(capture_dir, "suricata_logs", "eve.json")
    db_path = os.path.join(capture_dir, "forensics.db")
    
    print(f"Connecting to SQLite database at {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Ingest Zeek Logs
        ingest_zeek_logs(cursor, zeek_dir)
        
        # Ingest Suricata Alerts
        ingest_suricata_alerts(cursor, suricata_eve)
        
        conn.commit()
        print("Ingestion completed successfully.")
    except Exception as e:
        conn.rollback()
        print(f"Ingestion failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
