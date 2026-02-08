#!/usr/bin/env python3
"""
Script para forzar la creación de columnas image_url e image_type en coach_community
Este script debe ejecutarse directamente en Railway para solucionar el problema de las columnas faltantes.
"""

import os
import sys
from sqlalchemy import create_engine, text, inspect

def get_database_url():
    """Obtener la URL de la base de datos"""
    # Primero intentar con DATABASE_URL (Railway)
    db_url = os.environ.get('DATABASE_URL')
    
    if not db_url:
        # Si no está, usar SQLite local
        db_url = 'sqlite:///instance/assessments.db'
        print(f"⚠️ DATABASE_URL no encontrada, usando SQLite local: {db_url}")
    else:
        print(f"✅ Usando base de datos: {db_url[:30]}...")
    
    return db_url

def check_and_add_columns():
    """Verificar y agregar columnas faltantes"""
    try:
        db_url = get_database_url()
        engine = create_engine(db_url)
        
        print("\n" + "="*70)
        print("🔍 VERIFICACIÓN DE COLUMNAS EN coach_community")
        print("="*70 + "\n")
        
        # Obtener información de la tabla
        inspector = inspect(engine)
        
        # Verificar si la tabla existe
        if 'coach_community' not in inspector.get_table_names():
            print("❌ ERROR: La tabla 'coach_community' no existe")
            return False
        
        # Obtener columnas existentes
        columns = [col['name'] for col in inspector.get_columns('coach_community')]
        print(f"📋 Columnas actuales en coach_community: {', '.join(columns)}\n")
        
        # Verificar columnas faltantes
        missing_columns = []
        if 'image_url' not in columns:
            missing_columns.append('image_url')
        if 'image_type' not in columns:
            missing_columns.append('image_type')
        
        if not missing_columns:
            print("✅ ¡Todas las columnas necesarias ya existen!")
            print("   - image_url: ✓")
            print("   - image_type: ✓")
            return True
        
        print(f"⚠️ Columnas faltantes detectadas: {', '.join(missing_columns)}\n")
        
        # Agregar columnas faltantes
        with engine.connect() as conn:
            for column in missing_columns:
                try:
                    if column == 'image_url':
                        print(f"🔧 Agregando columna 'image_url'...")
                        conn.execute(text("ALTER TABLE coach_community ADD COLUMN image_url TEXT"))
                        conn.commit()
                        print("   ✅ Columna 'image_url' agregada exitosamente")
                    
                    elif column == 'image_type':
                        print(f"🔧 Agregando columna 'image_type'...")
                        conn.execute(text("ALTER TABLE coach_community ADD COLUMN image_type VARCHAR(20) DEFAULT 'catalog'"))
                        conn.commit()
                        print("   ✅ Columna 'image_type' agregada exitosamente")
                
                except Exception as e:
                    print(f"   ❌ Error agregando columna '{column}': {e}")
                    conn.rollback()
                    raise
        
        # Verificar nuevamente
        print("\n🔍 Verificación post-migración...")
        inspector = inspect(engine)
        columns_after = [col['name'] for col in inspector.get_columns('coach_community')]
        print(f"📋 Columnas después de migración: {', '.join(columns_after)}\n")
        
        if 'image_url' in columns_after and 'image_type' in columns_after:
            print("="*70)
            print("✅ ¡MIGRACIÓN COMPLETADA EXITOSAMENTE!")
            print("="*70)
            print("\n✓ La tabla coach_community ahora tiene todas las columnas necesarias")
            print("✓ La creación de comunidades debería funcionar correctamente\n")
            return True
        else:
            print("❌ ERROR: Las columnas no se agregaron correctamente")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR CRÍTICO: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("\n🚀 Iniciando script de migración forzada...\n")
    success = check_and_add_columns()
    
    if success:
        print("\n✅ Script completado con éxito")
        sys.exit(0)
    else:
        print("\n❌ Script falló")
        sys.exit(1)
