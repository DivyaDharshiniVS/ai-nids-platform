"""
data_manager.py - SQLite Persistence & Data Management Layer
AI-Based Network Intrusion Detection System

Implements structured, persistent local storage using SQLite for:
1. User Authentication & Role-Based Access Control (RBAC)
2. Network Traffic Scan History
3. Security Incident Alerts
4. System Configuration & Audit Logs

Ensures safe SQL transactions, parameterization against injection,
and automatic schema creation without data loss across application reruns.
"""

import sqlite3
import json
import os
import datetime
import hashlib
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "nids_platform.db")

def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Generates a secure SHA-256 hash for password storage and verification."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. User Authentication & Access Control Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'SOC Analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Network Traffic Scan History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_ref TEXT UNIQUE NOT NULL,
        scan_date TEXT NOT NULL,
        total_packets INTEGER NOT NULL,
        normal_count INTEGER NOT NULL,
        malicious_count INTEGER NOT NULL,
        anomaly_rate REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Security Incident Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_ref TEXT NOT NULL,
        scan_ref TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        alert_message TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Legacy Support Tables (Preserved for compatibility)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS booking_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref_code TEXT UNIQUE NOT NULL,
        guide_id TEXT NOT NULL,
        guide_name TEXT NOT NULL,
        traveler_name TEXT NOT NULL,
        traveler_email TEXT NOT NULL,
        traveler_phone TEXT NOT NULL,
        tour_date TEXT NOT NULL,
        party_size INTEGER NOT NULL,
        tour_notes TEXT,
        daily_fee INTEGER NOT NULL,
        city TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Confirmed (Demo)',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS saved_itineraries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        itinerary_ref TEXT UNIQUE NOT NULL,
        destination_id TEXT NOT NULL,
        destination_name TEXT NOT NULL,
        duration_days INTEGER NOT NULL,
        travelers_count INTEGER NOT NULL,
        total_budget REAL NOT NULL,
        estimated_cost REAL NOT NULL,
        variance REAL NOT NULL,
        budget_status TEXT NOT NULL,
        travel_pace TEXT NOT NULL,
        itinerary_data_json TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        module_name TEXT NOT NULL,
        rating INTEGER NOT NULL,
        comments TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()

    # Seamless Migration: If nids_platform.db has 0 scans and legacy tourism_platform.db exists, copy over
    try:
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        if cursor.fetchone()[0] == 0:
            legacy_db = os.path.join(os.path.dirname(__file__), "tourism_platform.db")
            if os.path.exists(legacy_db):
                legacy_conn = sqlite3.connect(legacy_db)
                legacy_conn.row_factory = sqlite3.Row
                l_cursor = legacy_conn.cursor()
                
                # Check legacy scans
                l_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
                if l_cursor.fetchone():
                    l_cursor.execute("SELECT * FROM scan_history")
                    for row in l_cursor.fetchall():
                        cursor.execute("""
                        INSERT OR IGNORE INTO scan_history (scan_ref, scan_date, total_packets, normal_count, malicious_count, anomaly_rate)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """, (row["scan_ref"], row["scan_date"], row["total_packets"], row["normal_count"], row["malicious_count"], row["anomaly_rate"]))
                
                # Check legacy alerts
                l_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_alerts'")
                if l_cursor.fetchone():
                    l_cursor.execute("SELECT * FROM security_alerts")
                    for row in l_cursor.fetchall():
                        cursor.execute("""
                        INSERT OR IGNORE INTO security_alerts (alert_ref, scan_ref, timestamp, source_ip, dest_ip, protocol, threat_type, severity, alert_message, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (row["alert_ref"], row["scan_ref"], row["timestamp"], row["source_ip"], row["dest_ip"], row["protocol"], row["threat_type"], row["severity"], row["alert_message"], row["status"]))
                
                conn.commit()
                legacy_conn.close()
    except Exception as e:
        print(f"[Database Migration Warning] {e}")

    conn.close()

    # Seed demo admin account on launch
    seed_default_admin()

# ------------------------------------------------------------------------------
# BOOKING REQUEST OPERATIONS
# ------------------------------------------------------------------------------

def save_booking_request(
    ref_code: str,
    guide_id: str,
    guide_name: str,
    traveler_name: str,
    traveler_email: str,
    traveler_phone: str,
    tour_date: str,
    party_size: int,
    tour_notes: str,
    daily_fee: int,
    city: str
) -> bool:
    """Inserts a new verified demonstration booking record into SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO booking_requests 
        (ref_code, guide_id, guide_name, traveler_name, traveler_email, traveler_phone, tour_date, party_size, tour_notes, daily_fee, city)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ref_code, guide_id, guide_name, traveler_name.strip(),
            traveler_email.strip(), traveler_phone.strip(), str(tour_date),
            int(party_size), tour_notes.strip() if tour_notes else "",
            int(daily_fee), city
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[Database Error] save_booking_request failed: {e}")
        return False
    finally:
        conn.close()

def get_all_booking_requests(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recorded demonstration bookings ordered by newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM booking_requests ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results

# ------------------------------------------------------------------------------
# ITINERARY PERSISTENCE OPERATIONS
# ------------------------------------------------------------------------------

def save_itinerary(
    itinerary_ref: str,
    destination_id: str,
    destination_name: str,
    duration_days: int,
    travelers_count: int,
    total_budget: float,
    estimated_cost: float,
    variance: float,
    budget_status: str,
    travel_pace: str,
    itinerary_data: Dict[str, Any]
) -> bool:
    """Saves a generated itinerary for persistence across sessions."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT OR REPLACE INTO saved_itineraries
        (itinerary_ref, destination_id, destination_name, duration_days, travelers_count, total_budget, estimated_cost, variance, budget_status, travel_pace, itinerary_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            itinerary_ref, destination_id, destination_name, int(duration_days),
            int(travelers_count), float(total_budget), float(estimated_cost),
            float(variance), budget_status, travel_pace, json.dumps(itinerary_data)
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[Database Error] save_itinerary failed: {e}")
        return False
    finally:
        conn.close()

def get_saved_itineraries(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves saved itineraries from SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, itinerary_ref, destination_id, destination_name, duration_days, travelers_count, total_budget, estimated_cost, variance, budget_status, travel_pace, created_at 
    FROM saved_itineraries ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results

# ------------------------------------------------------------------------------
# FEEDBACK OPERATIONS
# ------------------------------------------------------------------------------

def save_feedback(module_name: str, rating: int, comments: str) -> bool:
    """Saves user feedback for academic quality assurance."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO user_feedback (module_name, rating, comments)
        VALUES (?, ?, ?)
        """, (module_name, int(rating), comments.strip()))
        conn.commit()
        return True
    except Exception as e:
        print(f"[Database Error] save_feedback failed: {e}")
        return False
    finally:
        conn.close()

def get_db_stats() -> Dict[str, int]:
    """Returns total counts for dashboard KPIs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM booking_requests")
        bookings = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM saved_itineraries")
        itineraries = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM user_feedback")
        feedback = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        scans = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM security_alerts")
        alerts = cursor.fetchone()[0]
        return {
            "total_bookings": bookings,
            "total_saved_itineraries": itineraries,
            "total_feedback": feedback,
            "total_scans": scans,
            "total_alerts": alerts
        }
    except Exception:
        return {"total_bookings": 0, "total_saved_itineraries": 0, "total_feedback": 0, "total_scans": 0, "total_alerts": 0}
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# NIDS SCAN & ALERT OPERATIONS
# ------------------------------------------------------------------------------

def save_scan_record(
    scan_ref: str,
    total_packets: int,
    normal_count: int,
    malicious_count: int,
    anomaly_rate: float,
    scan_date: Optional[str] = None
) -> bool:
    """Inserts a completed network traffic analysis record into SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if scan_date is None:
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cursor.execute("""
        INSERT OR REPLACE INTO scan_history
        (scan_ref, scan_date, total_packets, normal_count, malicious_count, anomaly_rate)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_ref, scan_date, int(total_packets),
            int(normal_count), int(malicious_count), float(anomaly_rate)
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[Database Error] save_scan_record failed: {e}")
        return False
    finally:
        conn.close()

def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recorded network scans ordered by newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM scan_history ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results

def save_alerts_batch(alerts: List[Dict[str, Any]], scan_ref: str) -> int:
    """Saves generated security alerts into SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    saved = 0
    try:
        for a in alerts:
            cursor.execute("""
            INSERT INTO security_alerts
            (alert_ref, scan_ref, timestamp, source_ip, dest_ip, protocol, threat_type, severity, alert_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a.get("alert_id", "ALT-0000"),
                scan_ref,
                a.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                a.get("source_ip", "0.0.0.0"),
                a.get("dest_ip", "0.0.0.0"),
                a.get("protocol", "TCP"),
                a.get("threat_type", "Unknown"),
                a.get("severity", "Medium"),
                a.get("alert_message", "")
            ))
            saved += 1
        conn.commit()
    except Exception as e:
        print(f"[Database Error] save_alerts_batch failed: {e}")
    finally:
        conn.close()
    return saved

def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recorded security alerts ordered by newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results

# ------------------------------------------------------------------------------
# USER AUTHENTICATION & ACCESS CONTROL OPERATIONS
# ------------------------------------------------------------------------------

def create_user(username: str, password: str, role: str = "SOC Analyst") -> bool:
    """Creates a new user record with SHA-256 hashed password. Returns True on success."""
    username = username.strip()
    if not username or not password:
        return False

    password_hash = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        """, (username, password_hash, role.strip()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    except Exception as e:
        print(f"[Database Error] create_user failed: {e}")
        return False
    finally:
        conn.close()

def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verifies user credentials. Returns user dictionary on success, or None on failure."""
    username = username.strip()
    if not username or not password:
        return None

    password_hash = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT id, username, role, created_at
        FROM users
        WHERE username = ? AND password_hash = ?
        """, (username, password_hash))
        row = cursor.fetchone()
        if row:
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "created_at": row["created_at"]
            }
        return None
    except Exception as e:
        print(f"[Database Error] verify_user failed: {e}")
        return None
    finally:
        conn.close()

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves public user context by username (excluding password hash)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT id, username, role, created_at FROM users WHERE username = ?
        """, (username.strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def get_all_users() -> List[Dict[str, Any]]:
    """Retrieves all registered users without password hashes."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def seed_default_admin():
    """Seeds default demo admin account if not already present."""
    if not get_user_by_username("admin"):
        create_user(username="admin", password="admin123", role="SOC Admin")

def clear_scan_history() -> bool:
    """Clears all scan history and security incident alerts from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM scan_history;")
        cursor.execute("DELETE FROM security_alerts;")
        conn.commit()
        return True
    except Exception as e:
        print(f"[Database Error] clear_scan_history failed: {e}")
        return False
    finally:
        conn.close()

# Auto-initialize database on import
init_db()
