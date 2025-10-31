#!/usr/bin/env python3
"""
Script para agregar la columna assessment_id a la tabla invitation
"""
import os
import sys
from app import app, db
from sqlalchemy import text

def add_assessment_id_column():
    """Agregar columna assessment_id a la tabla invitation si no existe"""
    
    with app.app_context():
        try:
            # Detectar tipo de base de datos
            db_url = str(db.engine.url)
            is_postgres = 'postgresql' in db_url
            is_sqlite = 'sqlite' in db_url
            
            print(f"🔍 Base de datos detectada: {'PostgreSQL' if is_postgres else 'SQLite' if is_sqlite else 'Desconocida'}")
            
            # Verificar si la columna ya existe
            if is_postgres:
                check_query = text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='invitation' AND column_name='assessment_id'
                """)
            else:  # SQLite
                check_query = text("""
                    SELECT COUNT(*) as count
                    FROM pragma_table_info('invitation')
                    WHERE name='assessment_id'
                """)
            
            result = db.session.execute(check_query).fetchone()
            
            if is_postgres and result:
                print("✅ La columna 'assessment_id' ya existe en la tabla 'invitation'")
                return True
            elif is_sqlite and result and result[0] > 0:
                print("✅ La columna 'assessment_id' ya existe en la tabla 'invitation'")
                return True
            
            print("🔧 Agregando columna 'assessment_id' a la tabla 'invitation'...")
            
            # Agregar la columna assessment_id según el tipo de base de datos
            if is_postgres:
                alter_query = text("""
                    ALTER TABLE invitation 
                    ADD COLUMN assessment_id INTEGER,
                    ADD CONSTRAINT fk_invitation_assessment 
                        FOREIGN KEY (assessment_id) 
                        REFERENCES assessment(id) 
                        ON DELETE SET NULL
                """)
            else:  # SQLite
                # SQLite no soporta ADD CONSTRAINT en ALTER TABLE, solo ADD COLUMN
                alter_query = text("""
                    ALTER TABLE invitation 
                    ADD COLUMN assessment_id INTEGER
                """)
            
            db.session.execute(alter_query)
            db.session.commit()
            
            print("✅ Columna 'assessment_id' agregada exitosamente")
            
            # Crear índice para mejorar rendimiento
            print("🔧 Creando índice para assessment_id...")
            index_query = text("""
                CREATE INDEX IF NOT EXISTS idx_invitation_assessment_id 
                ON invitation(assessment_id)
            """)
            
            db.session.execute(index_query)
            db.session.commit()
            
            print("✅ Índice creado exitosamente")
            print("✅ Migración completada con éxito")
            
            return True
            
        except Exception as e:
            print(f"❌ Error durante la migración: {str(e)}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("=" * 60)
    print("MIGRACIÓN: Agregar columna assessment_id a tabla invitation")
    print("=" * 60)
    
    success = add_assessment_id_column()
    
    if success:
        print("\n✅ Migración completada exitosamente")
        sys.exit(0)
    else:
        print("\n❌ La migración falló")
        sys.exit(1)
