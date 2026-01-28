#!/usr/bin/env python3
"""
Migration: Add activation_token and activation_expires to coach_request table
Purpose: Support secure activation link system (no passwords in emails)
"""

import os
import sys
from datetime import datetime
from sqlalchemy import create_engine, inspect, text

# Configurar base de datos
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("❌ Error: DATABASE_URL no está configurado")
    sys.exit(1)

# Fix para Railway (postgres:// -> postgresql://)
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

print(f"📊 Conectando a base de datos...")
engine = create_engine(DATABASE_URL)

def check_table_exists():
    """Verificar si la tabla coach_request existe"""
    inspector = inspect(engine)
    return 'coach_request' in inspector.get_table_names()

def check_column_exists(column_name):
    """Verificar si una columna existe en coach_request"""
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('coach_request')]
    return column_name in columns

def add_activation_fields():
    """Agregar campos activation_token y activation_expires"""
    with engine.begin() as conn:
        # Agregar activation_token
        if not check_column_exists('activation_token'):
            print("➕ Agregando columna activation_token...")
            conn.execute(text("""
                ALTER TABLE coach_request 
                ADD COLUMN activation_token VARCHAR(100) UNIQUE
            """))
            conn.execute(text("""
                CREATE INDEX idx_coach_request_activation_token 
                ON coach_request(activation_token)
            """))
            print("✅ Columna activation_token agregada con índice")
        else:
            print("⏭️  Columna activation_token ya existe")
        
        # Agregar activation_expires
        if not check_column_exists('activation_expires'):
            print("➕ Agregando columna activation_expires...")
            conn.execute(text("""
                ALTER TABLE coach_request 
                ADD COLUMN activation_expires TIMESTAMP
            """))
            print("✅ Columna activation_expires agregada")
        else:
            print("⏭️  Columna activation_expires ya existe")

def show_structure():
    """Mostrar estructura actualizada de la tabla"""
    inspector = inspect(engine)
    columns = inspector.get_columns('coach_request')
    
    print("\n📋 Estructura de coach_request:")
    print("-" * 60)
    for col in columns:
        nullable = "NULL" if col['nullable'] else "NOT NULL"
        print(f"  {col['name']:25} {str(col['type']):20} {nullable}")
    print("-" * 60)

if __name__ == '__main__':
    try:
        print("🚀 Iniciando migración: Add Activation Token Fields")
        print("=" * 60)
        
        # Verificar tabla existe
        if not check_table_exists():
            print("❌ Error: tabla coach_request no existe")
            print("   Ejecuta primero: python3 migration_add_coach_request_table.py")
            sys.exit(1)
        
        # Agregar campos
        add_activation_fields()
        
        # Mostrar estructura
        show_structure()
        
        print("\n✅ Migración completada exitosamente")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error en migración: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
