#!/usr/bin/env python3
"""
Migration: Add draft/publish fields to Assessment table (PostgreSQL)
Date: 2025-01-06
Description: Adds status, coach_id, and category columns to support draft/publish workflow
             This version works with PostgreSQL (production) and SQLite (local)
"""

import sys
import os
from sqlalchemy import create_engine, text, inspect
from datetime import datetime

def get_database_url():
    """Get database URL from environment or use local SQLite"""
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Railway uses postgres:// but SQLAlchemy needs postgresql://
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        print(f"✅ Using PostgreSQL database from DATABASE_URL")
        return database_url
    else:
        # Check for database in instance folder first (Flask default)
        if os.path.exists('instance/assessments.db'):
            print(f"✅ Using local SQLite database: instance/assessments.db")
            return 'sqlite:///instance/assessments.db'
        else:
            print(f"✅ Using local SQLite database: assessments.db")
            return 'sqlite:///assessments.db'

def run_migration():
    """Execute the migration to add new columns to assessment table"""
    
    print("=" * 70)
    print("🔄 MIGRATION: Add Assessment Draft/Publish Fields (PostgreSQL/SQLite)")
    print("=" * 70)
    
    try:
        database_url = get_database_url()
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # Get current table schema
            inspector = inspect(engine)
            current_columns = [col['name'] for col in inspector.get_columns('assessment')]
            print(f"\n📊 Current columns: {', '.join(current_columns)}")
            
            # Check if columns already exist
            columns_to_add = []
            if 'status' not in current_columns:
                columns_to_add.append('status')
            if 'coach_id' not in current_columns:
                columns_to_add.append('coach_id')
            if 'category' not in current_columns:
                columns_to_add.append('category')
            
            if not columns_to_add:
                print("\n✨ All columns already exist. Checking data...")
            else:
                print(f"\n🔧 Adding {len(columns_to_add)} new columns...")
                
                # Add each column
                if 'status' in columns_to_add:
                    print("   ➜ Adding column: status")
                    conn.execute(text("ALTER TABLE assessment ADD COLUMN status VARCHAR(20) DEFAULT 'published'"))
                    print("   ✅ status added successfully")
                
                if 'coach_id' in columns_to_add:
                    print("   ➜ Adding column: coach_id")
                    conn.execute(text("ALTER TABLE assessment ADD COLUMN coach_id INTEGER"))
                    print("   ✅ coach_id added successfully")
                
                if 'category' in columns_to_add:
                    print("   ➜ Adding column: category")
                    conn.execute(text("ALTER TABLE assessment ADD COLUMN category VARCHAR(100)"))
                    print("   ✅ category added successfully")
                
                # Create indexes for performance
                if 'status' in columns_to_add:
                    print("\n📑 Creating index on status column...")
                    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_assessment_status ON assessment(status)"))
                    print("   ✅ Index created")
                
                if 'coach_id' in columns_to_add:
                    print("📑 Creating index on coach_id column...")
                    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_assessment_coach_id ON assessment(coach_id)"))
                    print("   ✅ Index created")
            
            # CRITICAL: Update existing records to have 'published' status if NULL
            print("\n🔄 Updating existing assessments to 'published' status...")
            result = conn.execute(text("UPDATE assessment SET status = 'published' WHERE status IS NULL OR status = ''"))
            updated = result.rowcount
            print(f"   ✅ Updated {updated} existing records")
            
            # Commit changes
            conn.commit()
            print("\n💾 Changes committed to database")
            
            # Verify new schema
            print("\n📊 Verifying new schema...")
            new_columns = [col['name'] for col in inspector.get_columns('assessment')]
            print(f"   New columns: {', '.join(new_columns)}")
            
            # Show count of assessments by status
            print("\n📈 Current assessment statistics:")
            result = conn.execute(text("SELECT status, COUNT(*) FROM assessment GROUP BY status"))
            stats = result.fetchall()
            for status, count in stats:
                print(f"      • {status or 'NULL'}: {count} assessment(s)")
            
            # Show count by is_active
            print("\n📈 Active assessment statistics:")
            result = conn.execute(text("SELECT is_active, COUNT(*) FROM assessment GROUP BY is_active"))
            active_stats = result.fetchall()
            for is_active, count in active_stats:
                print(f"      • is_active={is_active}: {count} assessment(s)")
        
        print("\n" + "=" * 70)
        print("✅ MIGRATION COMPLETED SUCCESSFULLY")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        print(traceback.format_exc())
        print("=" * 70)
        return False


def check_migration_status():
    """Check if migration has been applied"""
    
    print("=" * 70)
    print("🔍 CHECKING MIGRATION STATUS")
    print("=" * 70)
    
    try:
        database_url = get_database_url()
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            inspector = inspect(engine)
            current_columns = [col['name'] for col in inspector.get_columns('assessment')]
            
            print(f"\n📊 Current assessment table columns:")
            for col in inspector.get_columns('assessment'):
                print(f"   • {col['name']}: {col['type']}")
            
            # Check specific columns
            print("\n🔍 Migration columns check:")
            for col in ['status', 'coach_id', 'category']:
                status = "✅ EXISTS" if col in current_columns else "❌ MISSING"
                print(f"   • {col}: {status}")
            
            # Check data
            if 'status' in current_columns:
                print("\n📈 Assessment status distribution:")
                result = conn.execute(text("SELECT status, COUNT(*) FROM assessment GROUP BY status"))
                for status, count in result.fetchall():
                    print(f"      • {status or 'NULL'}: {count}")
            
            if 'is_active' in current_columns:
                print("\n📈 Assessment is_active distribution:")
                result = conn.execute(text("SELECT is_active, COUNT(*) FROM assessment GROUP BY is_active"))
                for is_active, count in result.fetchall():
                    print(f"      • {is_active}: {count}")
        
        print("\n" + "=" * 70)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        print(traceback.format_exc())


if __name__ == '__main__':
    print("\n🚀 Assessment Draft/Publish Migration Tool (PostgreSQL/SQLite)\n")
    
    if len(sys.argv) > 1 and sys.argv[1] == '--check':
        check_migration_status()
    else:
        success = run_migration()
        sys.exit(0 if success else 1)
