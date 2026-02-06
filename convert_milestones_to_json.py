#!/usr/bin/env python3
"""
Script para convertir columna milestones de TEXT a JSON
"""
import os
import psycopg2

database_url = os.environ.get('DATABASE_URL', '')
if not database_url:
    print("❌ DATABASE_URL no configurada")
    exit(1)

database_url = database_url.replace('postgres://', 'postgresql://')

try:
    conn = psycopg2.connect(database_url)
    cur = conn.cursor()
    
    print("🔧 Convirtiendo columna milestones de TEXT a JSON...")
    print("-" * 80)
    
    # Paso 1: Eliminar el default existente
    print("1. Eliminando default...")
    cur.execute("""
        ALTER TABLE development_plan 
        ALTER COLUMN milestones DROP DEFAULT
    """)
    conn.commit()
    print("   ✅ Default eliminado")
    
    # Paso 2: Actualizar valores NULL a '[]'
    print("\n2. Actualizando valores NULL...")
    cur.execute("""
        UPDATE development_plan 
        SET milestones = '[]'
        WHERE milestones IS NULL OR milestones = ''
    """)
    conn.commit()
    print("   ✅ Valores NULL actualizados")
    
    # Paso 3: Convertir columna a JSON
    print("\n3. Convirtiendo columna a JSON...")
    cur.execute("""
        ALTER TABLE development_plan 
        ALTER COLUMN milestones TYPE JSON 
        USING milestones::json
    """)
    conn.commit()
    print("   ✅ Columna convertida a JSON")
    
    # Paso 4: Establecer nuevo default
    print("\n4. Estableciendo nuevo default...")
    cur.execute("""
        ALTER TABLE development_plan 
        ALTER COLUMN milestones SET DEFAULT '[]'::json
    """)
    conn.commit()
    print("   ✅ Default establecido")
    
    # Verificar
    print("\n" + "-" * 80)
    print("🔍 Verificando cambios...")
    cur.execute("""
        SELECT column_name, data_type, column_default
        FROM information_schema.columns
        WHERE table_name = 'development_plan'
        AND column_name = 'milestones'
    """)
    
    result = cur.fetchone()
    if result:
        print(f"\n  Columna: {result[0]}")
        print(f"  Tipo: {result[1]}")
        print(f"  Default: {result[2]}")
        
        if result[1] == 'json' or result[1] == 'jsonb':
            print("\n✅ ¡ÉXITO! La columna ahora es tipo JSON")
        else:
            print("\n⚠️  La columna sigue siendo tipo TEXT")
    
    cur.close()
    conn.close()
    print("\n" + "=" * 80)
    print("✅ Conversión completada")
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    try:
        conn.rollback()
    except:
        pass
    exit(1)
