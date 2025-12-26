#!/usr/bin/env python3
"""
Migration: Add draft/publish fields to Assessment table
Date: 2025-01-06
Description: Adds status, coach_id, and category columns to support draft/publish workflow
"""

import sys
import sqlite3
from datetime import datetime

DB_PATH = 'assessments.db'

def run_migration():
    """Execute the migration to add new columns to assessment table"""
    
    print("=" * 70)
    print("🔄 MIGRATION: Add Assessment Draft/Publish Fields")
    print("=" * 70)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        print("\n📊 Checking current assessment table schema...")
        cursor.execute("PRAGMA table_info(assessment)")
        current_columns = [row[1] for row in cursor.fetchall()]
        print(f"✅ Current columns: {', '.join(current_columns)}")
        
        # Check if columns already exist
        columns_to_add = []
        if 'status' not in current_columns:
            columns_to_add.append(('status', "VARCHAR(20) DEFAULT 'published'"))
        if 'coach_id' not in current_columns:
            columns_to_add.append(('coach_id', 'INTEGER'))
        if 'category' not in current_columns:
            columns_to_add.append(('category', 'VARCHAR(100)'))
        
        if not columns_to_add:
            print("\n✨ All columns already exist. No migration needed.")
            conn.close()
            return True
        
        print(f"\n🔧 Adding {len(columns_to_add)} new columns...")
        
        # Add each column
        for column_name, column_def in columns_to_add:
            sql = f"ALTER TABLE assessment ADD COLUMN {column_name} {column_def}"
            print(f"   ➜ Adding column: {column_name}")
            cursor.execute(sql)
            print(f"   ✅ {column_name} added successfully")
        
        # Create index on status for performance
        if 'status' in [col[0] for col in columns_to_add]:
            print("\n📑 Creating index on status column...")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_assessment_status ON assessment(status)")
            print("   ✅ Index created")
        
        # Create index on coach_id for performance
        if 'coach_id' in [col[0] for col in columns_to_add]:
            print("📑 Creating index on coach_id column...")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_assessment_coach_id ON assessment(coach_id)")
            print("   ✅ Index created")
        
        # Update existing records to have 'published' status
        print("\n🔄 Updating existing assessments to 'published' status...")
        cursor.execute("UPDATE assessment SET status = 'published' WHERE status IS NULL")
        updated = cursor.rowcount
        print(f"   ✅ Updated {updated} existing records")
        
        # Commit changes
        conn.commit()
        print("\n💾 Changes committed to database")
        
        # Verify new schema
        print("\n📊 Verifying new schema...")
        cursor.execute("PRAGMA table_info(assessment)")
        new_columns = [(row[1], row[2]) for row in cursor.fetchall()]
        print("   New schema:")
        for col_name, col_type in new_columns:
            print(f"      • {col_name}: {col_type}")
        
        # Show count of assessments by status
        print("\n📈 Current assessment statistics:")
        cursor.execute("SELECT status, COUNT(*) FROM assessment GROUP BY status")
        stats = cursor.fetchall()
        for status, count in stats:
            print(f"      • {status}: {count} assessment(s)")
        
        conn.close()
        
        print("\n" + "=" * 70)
        print("✅ MIGRATION COMPLETED SUCCESSFULLY")
        print("=" * 70)
        
        return True
        
    except sqlite3.Error as e:
        print(f"\n❌ DATABASE ERROR: {e}")
        print("=" * 70)
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        print("=" * 70)
        return False


def rollback_migration():
    """Rollback the migration (remove added columns)"""
    
    print("=" * 70)
    print("⏮️  ROLLBACK: Remove Assessment Draft/Publish Fields")
    print("=" * 70)
    print("\n⚠️  WARNING: SQLite doesn't support DROP COLUMN directly.")
    print("   Rollback would require recreating the entire table.")
    print("   This operation is not recommended for production databases.")
    print("\n   If you need to rollback, please:")
    print("   1. Export your data")
    print("   2. Drop the assessment table")
    print("   3. Recreate with old schema")
    print("   4. Re-import your data")
    print("=" * 70)


if __name__ == '__main__':
    print("\n🚀 Assessment Draft/Publish Migration Tool\n")
    
    if len(sys.argv) > 1 and sys.argv[1] == '--rollback':
        rollback_migration()
    else:
        success = run_migration()
        sys.exit(0 if success else 1)
