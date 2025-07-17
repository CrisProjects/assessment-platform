#!/usr/bin/env python3
"""
Script de migración para agregar índices a la base de datos existente
Este script debe ejecutarse después de las mejoras al modelo de datos
"""
import os
import sys
from datetime import datetime

# Agregar directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_indexes():
    """Crear índices en la base de datos existente"""
    try:
        from app_complete import app, db
        
        with app.app_context():
            print("🔄 MIGRATION: Iniciando creación de índices...")
            
            # Los índices se crearán automáticamente al hacer db.create_all()
            # ya que están definidos en los modelos
            db.create_all()
            
            print("✅ MIGRATION: Índices creados/actualizados exitosamente")
            
            # Verificar que las tablas existen
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            print(f"📊 MIGRATION: Tablas disponibles: {len(tables)}")
            for table in sorted(tables):
                print(f"   - {table}")
                
            # Verificar índices en tabla user
            user_indexes = inspector.get_indexes('user')
            print(f"📊 MIGRATION: Índices en tabla 'user': {len(user_indexes)}")
            for idx in user_indexes:
                print(f"   - {idx['name']}: {idx['column_names']}")
                
            return True
            
    except Exception as e:
        print(f"❌ MIGRATION: Error creando índices: {e}")
        return False

if __name__ == "__main__":
    print(f"🚀 MIGRATION: Iniciando migración de índices - {datetime.now()}")
    success = create_indexes()
    if success:
        print("🎉 MIGRATION: Migración completada exitosamente")
    else:
        print("💥 MIGRATION: Migración falló")
        sys.exit(1)
