#!/usr/bin/env python3
"""
Migración: Agregar columna 'type' a la tabla 'task' en PostgreSQL
Fecha: 2026-01-17
Razón: Error en producción - column task.type does not exist
"""
import os
import sys
from sqlalchemy import create_engine, text, inspect

def migrate_add_task_type_column():
    """Agregar columna 'type' a tabla task si no existe"""
    
    # Obtener DATABASE_URL de entorno
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("❌ ERROR: DATABASE_URL no está configurada")
        print("💡 Para Railway, ejecuta: railway run python migration_add_task_type.py")
        return False
    
    # Workaround para Railway/Heroku que usa postgres:// en lugar de postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    print(f"🔌 Conectando a base de datos...")
    print(f"   URL: {database_url[:30]}...")
    
    try:
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # Verificar si la columna ya existe
            inspector = inspect(engine)
            columns = [col['name'] for col in inspector.get_columns('task')]
            
            print(f"\n📋 Columnas actuales en tabla 'task':")
            for col in columns:
                print(f"   - {col}")
            
            if 'type' in columns:
                print(f"\n✅ La columna 'type' YA EXISTE en la tabla 'task'")
                print(f"   No se requiere migración")
                return True
            
            print(f"\n⚠️  La columna 'type' NO EXISTE en la tabla 'task'")
            print(f"🔧 Agregando columna 'type'...")
            
            # Agregar columna con valor por defecto
            conn.execute(text("""
                ALTER TABLE task 
                ADD COLUMN type VARCHAR(20) DEFAULT 'accion';
            """))
            conn.commit()
            
            print(f"✅ Columna 'type' agregada exitosamente")
            
            # Verificar que se agregó
            inspector = inspect(engine)
            columns_after = [col['name'] for col in inspector.get_columns('task')]
            
            if 'type' in columns_after:
                print(f"✅ VERIFICACIÓN: Columna 'type' confirmada en tabla 'task'")
                print(f"\n📋 Columnas después de migración:")
                for col in columns_after:
                    print(f"   - {col}")
                return True
            else:
                print(f"❌ ERROR: No se pudo verificar la columna 'type'")
                return False
                
    except Exception as e:
        print(f"\n❌ ERROR en migración: {e}")
        print(f"   Tipo: {type(e).__name__}")
        print(f"   Detalle: {str(e)}")
        import traceback
        print(f"\n{traceback.format_exc()}")
        return False
    finally:
        engine.dispose()

if __name__ == '__main__':
    print("="*70)
    print("🔧 MIGRACIÓN: Agregar columna 'type' a tabla 'task'")
    print("="*70)
    
    success = migrate_add_task_type_column()
    
    print("\n" + "="*70)
    if success:
        print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
        print("="*70)
        sys.exit(0)
    else:
        print("❌ MIGRACIÓN FALLÓ")
        print("="*70)
        sys.exit(1)
