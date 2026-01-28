#!/usr/bin/env python3
"""
Migración: Crear tabla coach_request para solicitudes de coaches pendientes
"""

import os
import sys
from datetime import datetime

# Configurar path para importar app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, CoachRequest

def migrate():
    """Crear tabla coach_request en la base de datos"""
    
    print("=" * 70)
    print("MIGRACIÓN: Crear tabla coach_request")
    print("=" * 70)
    
    with app.app_context():
        try:
            # Verificar si la tabla ya existe
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            
            if 'coach_request' in inspector.get_table_names():
                print("⚠️  La tabla 'coach_request' ya existe")
                print("✅ No se requieren cambios")
                return
            
            print("\n📋 Creando tabla coach_request...")
            
            # Crear la tabla
            CoachRequest.__table__.create(db.engine)
            
            print("✅ Tabla coach_request creada exitosamente")
            
            # Mostrar estructura de la tabla
            print("\n📊 Estructura de la tabla:")
            print("-" * 70)
            for column in CoachRequest.__table__.columns:
                nullable = "NULL" if column.nullable else "NOT NULL"
                print(f"  - {column.name}: {column.type} {nullable}")
            
            print("\n" + "=" * 70)
            print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
            print("=" * 70)
            print("\nAhora el sistema puede recibir solicitudes de coaches que")
            print("requieren aprobación del administrador antes de crear la cuenta.")
            
        except Exception as e:
            print(f"\n❌ Error durante la migración: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == '__main__':
    migrate()
