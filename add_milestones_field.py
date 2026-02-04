#!/usr/bin/env python3
"""
Script de migración: Agregar campo milestones a development_plan
"""
from app import app, db
from sqlalchemy import text

def add_milestones_column():
    with app.app_context():
        try:
            # Verificar si la columna ya existe
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='development_plan' 
                AND column_name='milestones'
            """))
            
            if result.fetchone():
                print("✅ La columna 'milestones' ya existe en development_plan")
                return
            
            print("📝 Agregando columna 'milestones' a development_plan...")
            
            # Agregar columna milestones (JSON)
            db.session.execute(text("""
                ALTER TABLE development_plan 
                ADD COLUMN milestones JSON DEFAULT NULL
            """))
            
            db.session.commit()
            print("✅ Columna 'milestones' agregada exitosamente")
            
            # Verificar planes existentes
            result = db.session.execute(text("SELECT COUNT(*) FROM development_plan"))
            count = result.fetchone()[0]
            print(f"📊 Planes existentes en la base de datos: {count}")
            
            if count > 0:
                print("ℹ️  Los planes existentes tendrán milestones=NULL hasta que se editen")
            
        except Exception as e:
            print(f"❌ Error durante la migración: {str(e)}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    print("\n🚀 Iniciando migración: Agregar campo milestones")
    print("=" * 50)
    add_milestones_column()
    print("=" * 50)
    print("✅ Migración completada\n")
