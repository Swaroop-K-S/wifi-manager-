"""
God Rules and Chronos Scheduler Engine
Handles automated time-of-day policies such as Bedtime internet lockouts,
Study Mode content restrictions, and VIP Gamer QoS priority.
"""
import time
import threading
from datetime import datetime
from backend.database import get_db

class GodScheduler:
    def __init__(self):
        self.running = False
        self.thread = None
        self._init_schedule_table()

    def _init_schedule_table(self):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS god_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            rule_type TEXT NOT NULL, -- 'bedtime', 'study_mode', 'vip_qos'
            target_scope TEXT DEFAULT 'all', -- 'all', 'guest', or specific MAC
            start_time TEXT NOT NULL, -- 'HH:MM' 24hr format e.g. '23:00'
            end_time TEXT NOT NULL,   -- 'HH:MM' 24hr format e.g. '06:30'
            is_active INTEGER DEFAULT 1,
            days_of_week TEXT DEFAULT 'Mon,Tue,Wed,Thu,Fri,Sat,Sun'
        )
        """)
        
        # Seed default Bedtime & Study mode policies if empty
        cursor.execute("SELECT COUNT(*) FROM god_schedules")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO god_schedules (rule_name, rule_type, target_scope, start_time, end_time, is_active)
                VALUES 
                ('Night Bedtime Freeze', 'bedtime', 'phones', '23:00', '06:30', 0),
                ('Afternoon Study Mode', 'study_mode', 'all', '16:00', '19:00', 0)
            """)
        conn.commit()
        conn.close()

    def is_current_time_in_range(self, start_str: str, end_str: str) -> bool:
        """Determines if current local time falls within start and end time strings."""
        try:
            now = datetime.now()
            current_min = now.hour * 60 + now.minute
            
            sh, sm = map(int, start_str.split(":"))
            eh, em = map(int, end_str.split(":"))
            start_min = sh * 60 + sm
            end_min = eh * 60 + em
            
            if start_min <= end_min:
                return start_min <= current_min <= end_min
            else: # Overnight range (e.g. 23:00 to 06:30)
                return current_min >= start_min or current_min <= end_min
        except Exception:
            return False

    def evaluate_policies(self):
        """Evaluates active schedules and enforces policies."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM god_schedules WHERE is_active = 1")
        active_rules = [dict(row) for row in cursor.fetchall()]

        for rule in active_rules:
            is_triggered = self.is_current_time_in_range(rule["start_time"], rule["end_time"])
            if rule["rule_type"] == "bedtime":
                if is_triggered:
                    # Enforce bedtime pause on mobile phones
                    cursor.execute("UPDATE devices SET is_paused = 1 WHERE device_type = 'phone' AND is_paused = 0")
            elif rule["rule_type"] == "study_mode":
                if is_triggered:
                    # Ensure social media and gaming categories are active in blacklist
                    for cat in ["Social Media", "Gaming"]:
                        cursor.execute("UPDATE blacklist_rules SET is_active = 1 WHERE target = ?", (cat,))
        conn.commit()
        conn.close()

    def start_loop(self):
        if self.running:
            return
        self.running = True

        def _loop():
            while self.running:
                try:
                    self.evaluate_policies()
                except Exception as e:
                    print("Scheduler error:", e)
                time.sleep(30) # Check every 30 seconds

        self.thread = threading.Thread(target=_loop, daemon=True)
        self.thread.start()

god_scheduler = GodScheduler()
god_scheduler.start_loop()
