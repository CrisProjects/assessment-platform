#!/usr/bin/env python3
"""
Migración: Agregar campo coach_notes a tabla User
Permite a los coaches guardar notas sobre sus coachees
"""
import sqlite3
import psycopg2
from psycopg2 import sql
import os
from urllib.parse import urlparse

def migrate_sqlite():
    """Migración para SQLite (desarrollo local)"""
    print("🔄 Migrando base de datos SQLite...")
    
    try:
        conn = sqlite3.connect('efectocoach.db')
        cursor = conn.cursor()
        
        # Verificar si la columna ya existe
        cursor.execute("PRAGMA table_info(user)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'coach_notes' in columns:
            print("✅ Campo 'coach_notes' ya existe en SQLite")
            conn.close()
            return True
        
        # Agregar columna
        cursor.execute("""
            ALTER TABLE user 
            ADD COLUMN coach_notes TEXT
        """)
        
        conn.commit()
        conn.close()
        
        print("✅ Campo 'coach_notes' agregado exitosamente a SQLite")
        return True
        
    except Exception as e:
        print(f"❌ Error en migración SQLite: {e}")
        return False

def migrate_postgresql():
    """Migración para PostgreSQL (producción Railway)"""
    print("🔄 Migrando base de datos PostgreSQL...")
    
    database_url = os.getenv('DATABASE_URL')
    if not database_url or database_url == '':
        print("⚠️  DATABASE_URL no configurada, saltando PostgreSQL")
        return True
    
    # Railway usa postgres:// pero psycopg2 necesita postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    try:
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Verificar si la columna ya existe
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='user' AND column_name='coach_notes'
        """)
        
        if cursor.fetchone():
            print("✅ Campo 'coach_notes' ya existe en PostgreSQL")
            conn.close()
            return True
        
        # Agregar columna
        cursor.execute("""
            ALTER TABLE "user" 
            ADD COLUMN coach_notes TEXT
        """)
        
        conn.commit()
        conn.close()
        
        print("✅ Campo 'coach_notes' agregado exitosamente a PostgreSQL")
        return True
        
    except Exception as e:
        print(f"❌ Error en migración PostgreSQL: {e}")
        return False

def main():
    """Ejecutar migraciones para ambas bases de datos"""
    print("=" * 60)
    print("MIGRACIÓN: Agregar campo coach_notes a tabla User")
    print("=" * 60)
    print()
    
    success = True
    
    # Migrar SQLite
    if not migrate_sqlite():
        success = False
    
    print()
    
    # Migrar PostgreSQL
    if not migrate_postgresql():
        success = False
    
    print()
    print("=" * 60)
    if success:
        print("✅ Migración completada exitosamente")
    else:
        print("⚠️  Migración completada con algunos errores")
    print("=" * 60)

if __name__ == '__main__':
    main()
