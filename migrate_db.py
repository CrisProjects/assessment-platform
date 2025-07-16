#!/usr/bin/env python3
"""
Script para migrar la base de datos agregando nuevos campos a la tabla Invitation
"""
import sqlite3
import os

def migrate_database():
    """Migrar la base de datos agregando campos faltantes"""
    db_path = 'assessments.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Base de datos {db_path} no encontrada")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Verificar si la tabla existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='invitation'")
        if not cursor.fetchone():
            print("❌ Tabla 'invitation' no encontrada")
            return False
        
        # Verificar columnas existentes
        cursor.execute("PRAGMA table_info(invitation)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"📋 Columnas actuales: {columns}")
        
        # Agregar columna coachee_id si no existe
        if 'coachee_id' not in columns:
            cursor.execute("ALTER TABLE invitation ADD COLUMN coachee_id INTEGER")
            print("✅ Agregada columna 'coachee_id'")
        else:
            print("ℹ️  Columna 'coachee_id' ya existe")
        
        # Agregar columna message si no existe
        if 'message' not in columns:
            cursor.execute("ALTER TABLE invitation ADD COLUMN message TEXT")
            print("✅ Agregada columna 'message'")
        else:
            print("ℹ️  Columna 'message' ya existe")
        
        conn.commit()
        conn.close()
        
        print("✅ Migración completada exitosamente")
        return True
        
    except Exception as e:
        print(f"❌ Error durante la migración: {e}")
        return False

if __name__ == "__main__":
    print("🔄 Iniciando migración de base de datos...")
    success = migrate_database()
    if success:
        print("🎉 Migración completada. La aplicación está lista para usar.")
    else:
        print("💥 Error en la migración. Revisa los logs.")
