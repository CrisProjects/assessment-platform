#!/usr/bin/env python3
"""
Script para agregar columnas assessment_id, accepted_at y status a la tabla invitation
"""
import os
import sys
from app import app, db
from sqlalchemy import text

def add_invitation_columns():
    """Agregar columnas faltantes a la tabla invitation si no existen"""
    
    with app.app_context():
        try:
            # Detectar tipo de base de datos
            db_url = str(db.engine.url)
            is_postgres = 'postgresql' in db_url
            is_sqlite = 'sqlite' in db_url
            
            print(f"🔍 Base de datos detectada: {'PostgreSQL' if is_postgres else 'SQLite' if is_sqlite else 'Desconocida'}")
            
            # Verificar qué columnas ya existen
            columns_to_add = []
            
            if is_postgres:
                check_query = text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='invitation' AND column_name IN ('assessment_id', 'accepted_at', 'status')
                """)
                existing_columns = [row[0] for row in db.session.execute(check_query).fetchall()]
            else:  # SQLite
                check_query = text("SELECT name FROM pragma_table_info('invitation')")
                existing_columns = [row[0] for row in db.session.execute(check_query).fetchall()]
            
            # Determinar qué columnas faltan
            required_columns = ['assessment_id', 'accepted_at', 'status']
            for col in required_columns:
                if col not in existing_columns:
                    columns_to_add.append(col)
            
            if not columns_to_add:
                print("✅ Todas las columnas ya existen en la tabla 'invitation'")
                return True
            
            print(f"🔧 Agregando columnas faltantes: {', '.join(columns_to_add)}...")
            
            # Agregar columnas según el tipo de base de datos
            for column in columns_to_add:
                try:
                    if column == 'assessment_id':
                        if is_postgres:
                            query = text("""
                                ALTER TABLE invitation 
                                ADD COLUMN assessment_id INTEGER,
                                ADD CONSTRAINT fk_invitation_assessment 
                                    FOREIGN KEY (assessment_id) 
                                    REFERENCES assessment(id) 
                                    ON DELETE SET NULL
                            """)
                        else:
                            query = text("ALTER TABLE invitation ADD COLUMN assessment_id INTEGER")
                        
                        db.session.execute(query)
                        db.session.commit()
                        print(f"✅ Columna 'assessment_id' agregada con foreign key")
                        
                        # Crear índice
                        index_query = text("CREATE INDEX IF NOT EXISTS idx_invitation_assessment_id ON invitation(assessment_id)")
                        db.session.execute(index_query)
                        db.session.commit()
                        
                    elif column == 'accepted_at':
                        query = text("ALTER TABLE invitation ADD COLUMN accepted_at TIMESTAMP")
                        db.session.execute(query)
                        db.session.commit()
                        print(f"✅ Columna 'accepted_at' agregada")
                        
                    elif column == 'status':
                        if is_postgres:
                            query = text("ALTER TABLE invitation ADD COLUMN status VARCHAR(20) DEFAULT 'pending'")
                        else:
                            query = text("ALTER TABLE invitation ADD COLUMN status VARCHAR(20) DEFAULT 'pending'")
                        db.session.execute(query)
                        db.session.commit()
                        print(f"✅ Columna 'status' agregada con default 'pending'")
                        
                        # Crear índice
                        index_query = text("CREATE INDEX IF NOT EXISTS idx_invitation_status ON invitation(status)")
                        db.session.execute(index_query)
                        db.session.commit()
                        
                except Exception as col_error:
                    print(f"⚠️  Error agregando columna '{column}': {col_error}")
                    db.session.rollback()
                    # Continuar con las demás columnas
            
            print("✅ Migración completada con éxito")
            
            return True
            
        except Exception as e:
            print(f"❌ Error durante la migración: {str(e)}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("=" * 60)
    print("MIGRACIÓN: Agregar columnas a tabla invitation")
    print("=" * 60)
    
    success = add_invitation_columns()
    
    if success:
        print("\n✅ Migración completada exitosamente")
        sys.exit(0)
    else:
        print("\n❌ La migración falló")
        sys.exit(1)
