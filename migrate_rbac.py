"""
Database migration script for RBAC update
Adds email, role, and last_login columns to existing users table
Creates new tables for audit_logs and alert_acknowledgments
"""
import sqlite3
import os
from ConfigManager import config

def migrate_database():
    db_path = config.get('database.path', 'ids_alerts.db')
    
    print(f"[*] Migrating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if email column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = {col[1] for col in cursor.fetchall()}
        
        # Add missing columns to users table
        if 'email' not in columns:
            print("[+] Adding 'email' column to users table")
            cursor.execute("ALTER TABLE users ADD COLUMN email VARCHAR(255)")
        
        if 'role' not in columns:
            print("[+] Adding 'role' column to users table")
            cursor.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'viewer' NOT NULL")
            # Update existing admin user to have admin role
            cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        
        if 'last_login' not in columns:
            print("[+] Adding 'last_login' column to users table")
            cursor.execute("ALTER TABLE users ADD COLUMN last_login DATETIME")
        
        # Create audit_logs table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username VARCHAR(80),
                action VARCHAR(100) NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("[+] Ensured audit_logs table exists")
        
        # Create indexes for audit_logs
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs (timestamp)")
        
        # Create alert_acknowledgments table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_acknowledgments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                username VARCHAR(80),
                notes TEXT,
                acknowledged_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("[+] Ensured alert_acknowledgments table exists")
        
        # Create index for alert_acknowledgments
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_alert_ack_alert_id ON alert_acknowledgments (alert_id)")
        
        conn.commit()
        print("[✓] Database migration completed successfully!")
        
    except Exception as e:
        conn.rollback()
        print(f"[-] Error during migration: {e}")
        raise
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()
