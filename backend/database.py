"""
Database and Persistence Layer for Wi-Fi God Mode Router Commander
Handles primary & guest networks, device metadata, connection bands, link rates, and firewall rules.
"""
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).parent / "wifi_god_mode.db"

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Devices table (primary and guest network with rich Wi-Fi connection metrics)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        ip TEXT NOT NULL,
        hostname TEXT,
        custom_name TEXT,
        vendor TEXT,
        device_type TEXT, -- 'phone', 'laptop', 'tablet', 'smart_tv', 'console', 'iot', 'router'
        os_info TEXT,
        network_type TEXT DEFAULT 'primary', -- 'primary' or 'guest'
        connection_type TEXT DEFAULT 'Wi-Fi 5 (802.11ac)', -- 'Wi-Fi 6', 'Wi-Fi 5', 'Wi-Fi 4', 'Ethernet LAN'
        wifi_band TEXT DEFAULT '5 GHz', -- '5 GHz' or '2.4 GHz'
        channel TEXT DEFAULT 'Ch 153',
        link_rate_mbps REAL DEFAULT 866.7,
        signal_percent INTEGER DEFAULT 94,
        status TEXT DEFAULT 'online',
        is_blocked INTEGER DEFAULT 0,
        is_paused INTEGER DEFAULT 0,
        bandwidth_limit_kbps INTEGER DEFAULT 0,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_download_bytes INTEGER DEFAULT 0,
        total_upload_bytes INTEGER DEFAULT 0,
        signal_dbm INTEGER DEFAULT -40,
        priority_level TEXT DEFAULT 'Normal'
    )
    """)
    
    # Automatic column migrations for existing databases
    migrations = [
        "ALTER TABLE devices ADD COLUMN network_type TEXT DEFAULT 'primary'",
        "ALTER TABLE devices ADD COLUMN connection_type TEXT DEFAULT 'Wi-Fi 5 (802.11ac)'",
        "ALTER TABLE devices ADD COLUMN wifi_band TEXT DEFAULT '5 GHz'",
        "ALTER TABLE devices ADD COLUMN channel TEXT DEFAULT 'Ch 153'",
        "ALTER TABLE devices ADD COLUMN link_rate_mbps REAL DEFAULT 866.7",
        "ALTER TABLE devices ADD COLUMN signal_percent INTEGER DEFAULT 94",
        "ALTER TABLE devices ADD COLUMN artificial_latency_ms INTEGER DEFAULT 0",
        "ALTER TABLE devices ADD COLUMN brand TEXT DEFAULT 'Generic'",
        "ALTER TABLE devices ADD COLUMN model_name TEXT DEFAULT ''",
        "ALTER TABLE activity_logs ADD COLUMN network_type TEXT DEFAULT 'primary'"
    ]
    for mig in migrations:
        try:
            cursor.execute(mig)
        except Exception:
            pass

    # Activity and accessed websites / domain queries table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_mac TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        network_type TEXT DEFAULT 'primary',
        domain TEXT NOT NULL,
        url_path TEXT,
        category TEXT,
        protocol TEXT DEFAULT 'HTTPS',
        port INTEGER DEFAULT 443,
        bytes_transferred INTEGER DEFAULT 0,
        action_taken TEXT DEFAULT 'ALLOWED',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Guest Network Configuration & Controls
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS guest_network_config (
        id INTEGER PRIMARY KEY,
        ssid_name TEXT DEFAULT 'AETHER-GUEST-WIFI',
        is_enabled INTEGER DEFAULT 1,
        is_isolated INTEGER DEFAULT 1,
        bandwidth_cap_mbps INTEGER DEFAULT 10,
        block_adult INTEGER DEFAULT 1,
        block_torrent INTEGER DEFAULT 1,
        block_social INTEGER DEFAULT 0
    )
    """)
    
    # Domain Blacklist / God Mode filtering rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blacklist_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_type TEXT NOT NULL,
        target TEXT NOT NULL UNIQUE,
        is_active INTEGER DEFAULT 1,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reason TEXT
    )
    """)

    cursor.execute("SELECT COUNT(*) FROM guest_network_config")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO guest_network_config (id, ssid_name, is_enabled, is_isolated, bandwidth_cap_mbps, block_adult, block_torrent, block_social)
            VALUES (1, 'AETHER-GUEST-WIFI', 1, 1, 10, 1, 1, 0)
        """)

    conn.commit()
    conn.close()

init_db()
