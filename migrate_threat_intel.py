#!/usr/bin/env python3
"""
Database Migration Script for Threat Intelligence
Adds threat intelligence columns to the alerts table
"""

import sys
import os
from sqlalchemy import create_engine, text

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ConfigManager import config

def migrate():
    """Add threat intelligence columns to alerts table"""
    db_path = config.get('database.path', 'ids_alerts.db')
    engine = create_engine(f'sqlite:///{db_path}')
    
    print("Starting threat intelligence migration...")
    
    with engine.connect() as conn:
        try:
            # Check if columns already exist
            result = conn.execute(text("PRAGMA table_info(alerts)"))
            columns = [row[1] for row in result]
            
            if 'abuse_score' in columns:
                print("✓ Migration already applied, skipping.")
                return
            
            # Add new columns
            print("Adding threat intelligence columns...")
            
            conn.execute(text("ALTER TABLE alerts ADD COLUMN abuse_score INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN is_known_threat BOOLEAN DEFAULT 0"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN threat_categories TEXT"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN total_reports INTEGER DEFAULT 0"))
            
            conn.commit()
            
            print("✓ Migration complete!")
            print("  Added columns:")
            print("    - abuse_score (INTEGER)")
            print("    - is_known_threat (BOOLEAN)")
            print("    - threat_categories (TEXT)")
            print("    - total_reports (INTEGER)")
            
        except Exception as e:
            print(f"✗ Migration failed: {e}")
            conn.rollback()
            raise

if __name__ == "__main__":
    migrate()
