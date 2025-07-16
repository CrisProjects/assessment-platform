#!/usr/bin/env python3
"""
Script para arreglar problemas de base de datos
"""
import sqlite3
import os

def fix_database_issues():
    """Arreglar problemas conocidos en la base de datos"""
    db_path = 'instance/assessments.db'
    
    if not os.path.exists(db_path):
        print(f"Base de datos no encontrada en {db_path}")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔧 Arreglando problemas de base de datos...")
        
        # 1. Verificar si existe la columna coachee_id en invitation
        cursor.execute("PRAGMA table_info(invitation)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'coachee_id' not in columns:
            print("  📝 Agregando columna coachee_id a tabla invitation...")
            cursor.execute("ALTER TABLE invitation ADD COLUMN coachee_id INTEGER")
        else:
            print("  ✅ Columna coachee_id ya existe")
        
        # 2. Arreglar campos de fecha vacíos
        print("  📝 Arreglando campos de fecha vacíos...")
        
        # Actualizar campos last_login vacíos
        cursor.execute("UPDATE user SET last_login = NULL WHERE last_login = ''")
        
        # Actualizar campos created_at vacíos con fecha actual
        cursor.execute("UPDATE user SET created_at = datetime('now') WHERE created_at = '' OR created_at IS NULL")
        
        # Actualizar campos expires_at vacíos en invitations
        cursor.execute("UPDATE invitation SET expires_at = datetime('now', '+30 days') WHERE expires_at = '' OR expires_at IS NULL")
        
        # Actualizar campos created_at vacíos en invitations
        cursor.execute("UPDATE invitation SET created_at = datetime('now') WHERE created_at = '' OR created_at IS NULL")
        
        conn.commit()
        
        print("  ✅ Base de datos arreglada exitosamente")
        
        # 3. Verificar usuarios existentes
        cursor.execute("SELECT COUNT(*) FROM user WHERE role = 'coachee'")
        coachee_count = cursor.fetchone()[0]
        
        if coachee_count == 0:
            print("  📝 Creando usuario coachee de prueba...")
            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash('coachee123')
            
            cursor.execute("""
                INSERT INTO user (username, email, full_name, role, password_hash, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, ('coachee', 'coachee@assessment.com', 'Coachee de Prueba', 'coachee', password_hash, 1))
            
            conn.commit()
            print("  ✅ Usuario coachee de prueba creado")
        else:
            print(f"  ✅ Ya existen {coachee_count} coachees")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error arreglando base de datos: {e}")

if __name__ == "__main__":
    fix_database_issues()
