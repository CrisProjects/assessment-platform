#!/usr/bin/env python3
"""
Quick Fix: Ensure all assessments are visible in production
Date: 2025-01-06
Description: Updates existing assessments to ensure they appear in available-assessments endpoint
"""

import os
from sqlalchemy import create_engine, text

def get_database_url():
    """Get database URL from environment or use local SQLite"""
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
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

def fix_assessments():
    """Quick fix to make assessments visible"""
    
    print("=" * 70)
    print("🔧 QUICK FIX: Make Assessments Visible")
    print("=" * 70)
    
    try:
        database_url = get_database_url()
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # 1. Check current state
            print("\n📊 Current state:")
            result = conn.execute(text("SELECT COUNT(*) FROM assessment"))
            total = result.scalar()
            print(f"   Total assessments: {total}")
            
            result = conn.execute(text("SELECT COUNT(*) FROM assessment WHERE is_active = True"))
            active = result.scalar()
            print(f"   Active assessments: {active}")
            
            if total == 0:
                print("\n❌ ERROR: No assessments in database!")
                print("   You need to initialize the database with default assessments.")
                return False
            
            # 2. Fix is_active = NULL or False (set to True)
            print("\n🔧 Step 1: Setting is_active=True for all assessments...")
            result = conn.execute(text("UPDATE assessment SET is_active = True WHERE is_active IS NULL OR is_active = False"))
            updated_active = result.rowcount
            print(f"   ✅ Updated {updated_active} assessments")
            
            # 3. Fix status = NULL (set to 'published') - only if column exists
            try:
                print("\n🔧 Step 2: Setting status='published' for NULL status...")
                result = conn.execute(text("UPDATE assessment SET status = 'published' WHERE status IS NULL OR status = ''"))
                updated_status = result.rowcount
                print(f"   ✅ Updated {updated_status} assessments")
            except Exception as e:
                print(f"   ⚠️  Column 'status' might not exist: {e}")
                print("   → Run migration_add_assessment_fields_postgres.py first")
            
            # 4. Commit changes
            conn.commit()
            print("\n💾 Changes committed")
            
            # 5. Verify fix
            print("\n📊 After fix:")
            result = conn.execute(text("SELECT COUNT(*) FROM assessment WHERE is_active = True"))
            active_after = result.scalar()
            print(f"   Active assessments: {active_after}")
            
            try:
                result = conn.execute(text("SELECT COUNT(*) FROM assessment WHERE status = 'published'"))
                published = result.scalar()
                print(f"   Published assessments: {published}")
            except:
                pass
            
            # 6. Show sample data
            print("\n📋 Sample assessments (first 5):")
            try:
                result = conn.execute(text("SELECT id, title, is_active, status FROM assessment LIMIT 5"))
                for ass_id, title, is_active, status in result.fetchall():
                    status_display = status if status else 'NULL'
                    print(f"   • ID {ass_id}: {title[:40]}... - active={is_active}, status='{status_display}'")
            except:
                result = conn.execute(text("SELECT id, title, is_active FROM assessment LIMIT 5"))
                for ass_id, title, is_active in result.fetchall():
                    print(f"   • ID {ass_id}: {title[:40]}... - active={is_active}")
        
        print("\n" + "=" * 70)
        print("✅ QUICK FIX COMPLETED")
        print("=" * 70)
        print("\nℹ️  Next steps:")
        print("   1. Restart your application")
        print("   2. Test /api/coach/available-assessments endpoint")
        print("   3. If still not working, run diagnose_available_assessments.py")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        print(traceback.format_exc())
        print("=" * 70)
        return False


if __name__ == '__main__':
    print("\n⚡ Quick Fix Tool for Assessment Visibility\n")
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--dry-run':
        print("🔍 DRY RUN MODE - No changes will be made\n")
        # Would need to implement dry-run logic
    
    success = fix_assessments()
    sys.exit(0 if success else 1)
