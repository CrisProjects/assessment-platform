#!/usr/bin/env python3
"""
Script para agregar constraint único a assessment_result
para prevenir duplicaciones de user_id + assessment_id
"""
import os
import sys
from sqlalchemy import text

# Agregar el directorio actual al path para importar el app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importar la aplicación Flask y modelos
from app import app, db

def main():
    with app.app_context():
        print("🚀 Agregando constraint único a assessment_result...")
        
        try:
            # Verificar si ya existe el constraint
            result = db.session.execute(text("""
                SELECT name FROM sqlite_master 
                WHERE type='index' 
                AND tbl_name='assessment_result' 
                AND name LIKE '%unique%'
            """)).fetchall()
            
            if result:
                print("ℹ️  Ya existe un constraint único")
                for row in result:
                    print(f"   - {row[0]}")
                return
            
            # Crear índice único para prevenir duplicados
            print("📝 Creando constraint único...")
            db.session.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_user_assessment 
                ON assessment_result(user_id, assessment_id)
            """))
            
            db.session.commit()
            print("✅ Constraint único creado exitosamente")
            print("🔒 Ahora es imposible crear duplicados de user_id + assessment_id")
            
            # Verificar que se creó correctamente
            result = db.session.execute(text("""
                SELECT name FROM sqlite_master 
                WHERE type='index' 
                AND tbl_name='assessment_result' 
                AND name='idx_unique_user_assessment'
            """)).fetchall()
            
            if result:
                print("✅ Verificación exitosa - Constraint activo")
            else:
                print("⚠️  Error: No se pudo verificar el constraint")
                
        except Exception as e:
            print(f"❌ Error creando constraint: {e}")
            db.session.rollback()

if __name__ == "__main__":
    main()
