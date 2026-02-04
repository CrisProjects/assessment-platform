#!/usr/bin/env python3
"""
Migración: Agregar campo 'category' a development_plan
Fecha: 2026-02-01
Descripción: Agrega el campo 'category' (personal/professional) a los planes de desarrollo
"""

from app import app, db
from sqlalchemy import text

def add_category_field():
    """Agregar campo category a development_plan"""
    
    with app.app_context():
        try:
            print("🔧 Agregando campo 'category' a development_plan...")
            
            # Intenta agregar la columna directamente
            try:
                db.session.execute(text("""
                    ALTER TABLE development_plan 
                    ADD COLUMN category VARCHAR(20) DEFAULT 'personal'
                """))
                
                db.session.commit()
                print("✅ Campo 'category' agregado exitosamente")
                
            except Exception as inner_e:
                if "duplicate column" in str(inner_e).lower() or "already exists" in str(inner_e).lower():
                    print("✅ La columna 'category' ya existe")
                    db.session.rollback()
                else:
                    raise
            
        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    add_category_field()
