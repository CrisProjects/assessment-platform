#!/usr/bin/env python3
"""
Script para actualizar valores de las columnas recién agregadas en assessment
"""
import os
import sys
from sqlalchemy import create_engine, text

print("🔧 ACTUALIZANDO VALORES DE ASSESSMENT EN PRODUCCIÓN")
print("=" * 60)
print()

database_url = input("Pega el DATABASE_URL de Railway: ").strip()

if not database_url:
    print("❌ No se proporcionó DATABASE_URL")
    sys.exit(1)

if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

try:
    engine = create_engine(database_url)
    
    print("\n✅ Conexión establecida")
    print("\n" + "=" * 60)
    print("VERIFICANDO DATOS ACTUALES")
    print("=" * 60)
    
    with engine.connect() as conn:
        # Ver estado actual
        result = conn.execute(text("""
            SELECT id, title, is_active, status, coach_id, category
            FROM assessment
            ORDER BY id
        """))
        
        rows = result.fetchall()
        print(f"\n📊 Total de evaluaciones: {len(rows)}")
        print()
        
        for row in rows:
            print(f"ID {row[0]}: {row[1]}")
            print(f"  is_active: {row[2]}")
            print(f"  status: {row[3]}")
            print(f"  coach_id: {row[4]}")
            print(f"  category: {row[5]}")
            print()
    
    print("=" * 60)
    print("ACTUALIZANDO VALORES NULL")
    print("=" * 60)
    
    with engine.begin() as conn:
        # Actualizar is_active NULL a TRUE
        result1 = conn.execute(text("""
            UPDATE assessment 
            SET is_active = TRUE 
            WHERE is_active IS NULL
        """))
        print(f"\n✅ Actualizadas {result1.rowcount} filas: is_active = TRUE")
        
        # Actualizar status NULL a 'published'
        result2 = conn.execute(text("""
            UPDATE assessment 
            SET status = 'published' 
            WHERE status IS NULL
        """))
        print(f"✅ Actualizadas {result2.rowcount} filas: status = 'published'")
        
        # Actualizar created_at NULL a NOW()
        result3 = conn.execute(text("""
            UPDATE assessment 
            SET created_at = NOW() 
            WHERE created_at IS NULL
        """))
        print(f"✅ Actualizadas {result3.rowcount} filas: created_at = NOW()")
    
    print("\n" + "=" * 60)
    print("VERIFICANDO RESULTADOS")
    print("=" * 60)
    
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT id, title, is_active, status
            FROM assessment
            ORDER BY id
        """))
        
        rows = result.fetchall()
        print()
        for row in rows:
            print(f"ID {row[0]}: {row[1]}")
            print(f"  is_active: {row[2]} ✓")
            print(f"  status: {row[3]} ✓")
            print()
    
    print("=" * 60)
    print("✅ ACTUALIZACIÓN COMPLETADA EXITOSAMENTE")
    print("=" * 60)
    print()
    print("Ahora Railway debería redesplegar automáticamente.")
    print("Si no, haz un redeploy manual en Railway.")
    
except Exception as e:
    print(f"\n❌ Error: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
