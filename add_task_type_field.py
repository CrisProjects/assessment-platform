#!/usr/bin/env python3
"""
Script para agregar el campo 'type' a la tabla task.
Este campo distingue entre 'accion' y 'meta'.
"""

import sys
import traceback
from app import app, db
from sqlalchemy import text

def add_task_type_field():
    """Agregar campo type a la tabla task"""
    
    with app.app_context():
        try:
            print("=" * 60)
            print("AGREGANDO CAMPO 'type' A LA TABLA TASK")
            print("=" * 60)
            
            # Verificar si la columna ya existe
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('task')]
            
            if 'type' in columns:
                print("✅ El campo 'type' ya existe en la tabla task")
                return True
            
            print("\n1. Agregando columna 'type' a la tabla task...")
            
            # Agregar la columna con valor por defecto
            db.session.execute(text("""
                ALTER TABLE task 
                ADD COLUMN type VARCHAR(20) DEFAULT 'accion'
            """))
            
            print("✅ Columna 'type' agregada exitosamente")
            
            # Commit de los cambios
            db.session.commit()
            print("\n✅ Migración completada exitosamente")
            
            # Verificar la estructura final
            print("\n2. Verificando estructura de la tabla task...")
            columns = [col['name'] for col in inspector.get_columns('task')]
            print(f"Columnas en task: {', '.join(columns)}")
            
            # Verificar datos
            result = db.session.execute(text("SELECT COUNT(*) FROM task"))
            count = result.scalar()
            print(f"\n📊 Total de tareas en la base de datos: {count}")
            
            if count > 0:
                result = db.session.execute(text("SELECT id, title, type FROM task LIMIT 5"))
                print("\nPrimeras 5 tareas:")
                for row in result:
                    print(f"  - ID: {row[0]}, Título: {row[1]}, Tipo: {row[2]}")
            
            return True
            
        except Exception as e:
            print(f"\n❌ ERROR durante la migración:")
            print(f"   {str(e)}")
            print(f"\n{traceback.format_exc()}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = add_task_type_field()
    sys.exit(0 if success else 1)
