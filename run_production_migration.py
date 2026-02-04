#!/usr/bin/env python3
"""
Script para ejecutar migraciones en producción (Railway)
"""

import os
import sys

# Ensure we're using production database
if 'DATABASE_URL' not in os.environ:
    print("❌ ERROR: DATABASE_URL no está configurada")
    print("Este script debe ejecutarse en el entorno de producción (Railway)")
    sys.exit(1)

print(f"🔗 Conectando a base de datos de producción...")
print(f"   Database: {os.environ.get('DATABASE_URL', '').split('@')[1] if '@' in os.environ.get('DATABASE_URL', '') else 'N/A'}")

# Import migrations
from add_category_to_development_plan import add_category_field
from add_milestones_field import add_milestones_field

def run_all_migrations():
    """Ejecutar todas las migraciones pendientes"""
    
    print("\n" + "="*60)
    print("🚀 EJECUTANDO MIGRACIONES EN PRODUCCIÓN")
    print("="*60 + "\n")
    
    migrations = [
        ("Agregar campo 'category'", add_category_field),
        ("Agregar campo 'milestones'", add_milestones_field),
    ]
    
    for name, migration_func in migrations:
        print(f"\n📦 Ejecutando: {name}")
        print("-" * 60)
        try:
            migration_func()
            print(f"✅ {name} - COMPLETADO")
        except Exception as e:
            print(f"❌ {name} - ERROR: {e}")
            # Continue with other migrations
            continue
    
    print("\n" + "="*60)
    print("✅ MIGRACIONES COMPLETADAS")
    print("="*60 + "\n")

if __name__ == '__main__':
    run_all_migrations()
