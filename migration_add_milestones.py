#!/usr/bin/env python3
"""
Migration: Add milestones column to development_plan table
Author: System
Date: 2024
"""

import sqlite3
import sys
from pathlib import Path

def run_migration():
    """Add milestones JSON column to development_plan table"""
    
    db_path = Path(__file__).parent / 'instance' / 'assessments.db'
    
    if not db_path.exists():
        print(f"❌ Database not found at: {db_path}")
        sys.exit(1)
    
    print(f"📂 Using database: {db_path}")
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(development_plan)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'milestones' in columns:
            print("✅ Column 'milestones' already exists in development_plan table")
            conn.close()
            return
        
        # Add milestones column
        print("🔄 Adding milestones column to development_plan table...")
        cursor.execute("""
            ALTER TABLE development_plan 
            ADD COLUMN milestones TEXT DEFAULT NULL
        """)
        
        conn.commit()
        print("✅ Migration completed successfully!")
        print("📊 Column 'milestones' added to development_plan table")
        
        # Verify
        cursor.execute("PRAGMA table_info(development_plan)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"📋 Current columns: {', '.join(columns)}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error during migration: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Migration: Add milestones column to development_plan")
    print("=" * 60)
    run_migration()
    print("=" * 60)
    print("✨ Migration finished!")
    print("=" * 60)
