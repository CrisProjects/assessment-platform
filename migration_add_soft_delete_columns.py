#!/usr/bin/env python3
"""
Migración: Agregar columnas de soft delete a la tabla user

Este script agrega las columnas necesarias para el sistema de eliminación
recuperable (soft delete):
- deleted_at: Fecha y hora de eliminación
- deleted_by: ID del administrador que eliminó al usuario
- deletion_reason: Razón de la eliminación

Fecha: 2026-02-09
"""

from app import app, db
from sqlalchemy import text

def run_migration():
    """Ejecutar migración para agregar columnas de soft delete"""
    with app.app_context():
        try:
            print("🔄 Iniciando migración de soft delete...")
            
            # Verificar si las columnas ya existen
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            existing_columns = [col['name'] for col in inspector.get_columns('user')]
            
            print(f"📋 Columnas actuales en tabla 'user': {len(existing_columns)}")
            
            # Lista de columnas a agregar
            columns_to_add = []
            
            if 'deleted_at' not in existing_columns:
                columns_to_add.append(('deleted_at', 'DATETIME'))
                print("  ➕ Se agregará: deleted_at")
            else:
                print("  ✅ Ya existe: deleted_at")
            
            if 'deleted_by' not in existing_columns:
                columns_to_add.append(('deleted_by', 'INTEGER'))
                print("  ➕ Se agregará: deleted_by")
            else:
                print("  ✅ Ya existe: deleted_by")
            
            if 'deletion_reason' not in existing_columns:
                columns_to_add.append(('deletion_reason', 'TEXT'))
                print("  ➕ Se agregará: deletion_reason")
            else:
                print("  ✅ Ya existe: deletion_reason")
            
            if not columns_to_add:
                print("\n✅ Todas las columnas ya existen. No se requiere migración.")
                return
            
            print(f"\n🔨 Agregando {len(columns_to_add)} columnas...")
            
            # Agregar columnas
            for column_name, column_type in columns_to_add:
                sql = f"ALTER TABLE user ADD COLUMN {column_name} {column_type}"
                print(f"  Ejecutando: {sql}")
                db.session.execute(text(sql))
            
            # Crear índices para mejor performance
            if 'deleted_at' in [col[0] for col in columns_to_add]:
                try:
                    db.session.execute(text("CREATE INDEX idx_user_deleted_at ON user(deleted_at)"))
                    print("  ✅ Índice creado: idx_user_deleted_at")
                except Exception as e:
                    if "already exists" not in str(e):
                        print(f"  ⚠️ No se pudo crear índice: {e}")
            
            db.session.commit()
            
            print("\n✅ Migración completada exitosamente!")
            print("\n📊 Verificando columnas finales...")
            
            # Verificar resultado
            inspector = inspect(db.engine)
            final_columns = [col['name'] for col in inspector.get_columns('user')]
            
            print(f"✅ deleted_at: {'deleted_at' in final_columns}")
            print(f"✅ deleted_by: {'deleted_by' in final_columns}")
            print(f"✅ deletion_reason: {'deletion_reason' in final_columns}")
            
            print("\n✨ Sistema de soft delete listo para usar")
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Error en migración: {str(e)}")
            import traceback
            traceback.print_exc()
            raise

if __name__ == '__main__':
    print("=" * 60)
    print("MIGRACIÓN: Agregar columnas de Soft Delete")
    print("=" * 60)
    print()
    
    run_migration()
    
    print()
    print("=" * 60)
    print("Migración finalizada")
    print("=" * 60)
