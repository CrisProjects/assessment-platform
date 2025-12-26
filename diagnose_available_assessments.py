#!/usr/bin/env python3
"""
Diagnostic: Check production assessments availability
Date: 2025-01-06
Description: Diagnoses why available-assessments endpoint returns empty in production
"""

import os
from sqlalchemy import create_engine, text, inspect

def get_database_url():
    """Get database URL from environment or use local SQLite"""
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Railway uses postgres:// but SQLAlchemy needs postgresql://
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        print(f"✅ Using PostgreSQL database from DATABASE_URL")
        return database_url, 'postgresql'
    else:
        # Check for database in instance folder first (Flask default)
        if os.path.exists('instance/assessments.db'):
            print(f"✅ Using local SQLite database: instance/assessments.db")
            return 'sqlite:///instance/assessments.db', 'sqlite'
        else:
            print(f"✅ Using local SQLite database: assessments.db")
            return 'sqlite:///assessments.db', 'sqlite'

def diagnose_assessments():
    """Comprehensive diagnosis of assessment availability"""
    
    print("=" * 70)
    print("🔍 DIAGNOSIS: Assessment Availability Issue")
    print("=" * 70)
    
    try:
        database_url, db_type = get_database_url()
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # 1. Check table structure
            print("\n📊 1. ASSESSMENT TABLE STRUCTURE:")
            inspector = inspect(engine)
            columns = inspector.get_columns('assessment')
            for col in columns:
                default = f" DEFAULT={col.get('default', 'None')}" if col.get('default') else ""
                nullable = " NULL" if col.get('nullable', True) else " NOT NULL"
                print(f"   • {col['name']}: {col['type']}{nullable}{default}")
            
            # 2. Count all assessments
            print("\n📊 2. TOTAL ASSESSMENTS:")
            result = conn.execute(text("SELECT COUNT(*) FROM assessment"))
            total = result.scalar()
            print(f"   Total assessments: {total}")
            
            if total == 0:
                print("\n   ⚠️  WARNING: No assessments found in database!")
                print("   Action needed: Run create_additional_assessments() or seed database")
                return
            
            # 3. Check is_active distribution
            print("\n📊 3. IS_ACTIVE DISTRIBUTION:")
            result = conn.execute(text("SELECT is_active, COUNT(*) FROM assessment GROUP BY is_active"))
            for is_active, count in result.fetchall():
                print(f"   • is_active={is_active}: {count} assessments")
            
            # 4. Check status distribution (if column exists)
            column_names = [col['name'] for col in columns]
            if 'status' in column_names:
                print("\n📊 4. STATUS DISTRIBUTION:")
                result = conn.execute(text("SELECT status, COUNT(*) FROM assessment GROUP BY status"))
                for status, count in result.fetchall():
                    status_display = status if status else 'NULL'
                    print(f"   • status='{status_display}': {count} assessments")
            else:
                print("\n📊 4. STATUS COLUMN:")
                print("   ❌ Column 'status' does NOT exist!")
                print("   Action needed: Run migration_add_assessment_fields_postgres.py")
            
            # 5. Check coach_id distribution (if column exists)
            if 'coach_id' in column_names:
                print("\n📊 5. COACH_ID DISTRIBUTION:")
                result = conn.execute(text("SELECT coach_id, COUNT(*) FROM assessment GROUP BY coach_id"))
                for coach_id, count in result.fetchall():
                    coach_display = coach_id if coach_id else 'NULL (system)'
                    print(f"   • coach_id={coach_display}: {count} assessments")
            else:
                print("\n📊 5. COACH_ID COLUMN:")
                print("   ❌ Column 'coach_id' does NOT exist!")
            
            # 6. Simulate the available-assessments query
            print("\n📊 6. SIMULATING /api/coach/available-assessments QUERY:")
            print("   Query: SELECT * FROM assessment WHERE is_active = True")
            result = conn.execute(text("SELECT id, title, is_active, status FROM assessment WHERE is_active = True"))
            active_assessments = result.fetchall()
            print(f"   Result: {len(active_assessments)} assessments")
            
            if len(active_assessments) == 0:
                print("\n   ⚠️  PROBLEM FOUND: No active assessments!")
                print("   Checking why assessments are inactive...")
                
                # Check all assessments
                result = conn.execute(text("SELECT id, title, is_active FROM assessment LIMIT 10"))
                all_assessments = result.fetchall()
                print("\n   First 10 assessments in database:")
                for ass_id, title, is_active in all_assessments:
                    print(f"      • ID {ass_id}: {title} - is_active={is_active}")
            else:
                print("\n   ✅ Found active assessments:")
                for ass_id, title, is_active, status in active_assessments[:10]:
                    status_display = status if status else 'NULL'
                    print(f"      • ID {ass_id}: {title} - status='{status_display}'")
            
            # 7. Check for NULL values that might break the query
            print("\n📊 7. NULL VALUE CHECK:")
            result = conn.execute(text("SELECT COUNT(*) FROM assessment WHERE is_active IS NULL"))
            null_is_active = result.scalar()
            print(f"   • Assessments with is_active=NULL: {null_is_active}")
            
            if 'status' in column_names:
                result = conn.execute(text("SELECT COUNT(*) FROM assessment WHERE status IS NULL"))
                null_status = result.scalar()
                print(f"   • Assessments with status=NULL: {null_status}")
                
                if null_status > 0:
                    print("\n   ⚠️  PROBLEM: Some assessments have NULL status!")
                    print("   Action needed: Run migration to set status='published'")
            
            # 8. Recommendations
            print("\n📋 8. RECOMMENDATIONS:")
            
            if total == 0:
                print("   🔴 CRITICAL: Database has no assessments")
                print("      → Initialize database with default assessments")
            elif len(active_assessments) == 0:
                print("   🔴 CRITICAL: All assessments are inactive (is_active=False or NULL)")
                print("      → Update assessments: UPDATE assessment SET is_active = True")
            elif 'status' not in column_names:
                print("   🟡 WARNING: Missing 'status' column")
                print("      → Run: python3 migration_add_assessment_fields_postgres.py")
            elif null_status > 0:
                print("   🟡 WARNING: Some assessments have NULL status")
                print("      → Run: python3 migration_add_assessment_fields_postgres.py")
            else:
                print("   ✅ Database structure looks good!")
                print("   ℹ️  If issue persists, check application logs for query errors")
        
        print("\n" + "=" * 70)
        print("✅ DIAGNOSIS COMPLETED")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        print(traceback.format_exc())
        print("=" * 70)


if __name__ == '__main__':
    print("\n🩺 Assessment Availability Diagnostic Tool\n")
    diagnose_assessments()
