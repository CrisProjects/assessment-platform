#!/usr/bin/env python3
"""
Script para resetear la contraseña de un coachee
"""

import sys
import os
import sqlite3
from werkzeug.security import generate_password_hash

def reset_coachee_password(username, new_password):
    """Resetea la contraseña de un coachee"""
    
    try:
        # Conectar a la base de datos
        conn = sqlite3.connect('instance/assessments.db')
        cursor = conn.cursor()
        
        print(f"\n{'='*60}")
        print(f"🔐 Reseteando contraseña para coachee: {username}")
        print(f"{'='*60}\n")
        
        # Buscar coachee
        cursor.execute("""
            SELECT id, username, email, role
            FROM user
            WHERE (username = ? OR email = ?) AND role = 'coachee'
        """, (username, username))
        
        coachee = cursor.fetchone()
        
        if not coachee:
            print(f"❌ Coachee '{username}' no encontrado")
            print(f"   Verifica que el username/email sea correcto")
            return False
        
        coachee_id, coachee_username, coachee_email, role = coachee
        
        print(f"✅ Coachee encontrado:")
        print(f"   ID: {coachee_id}")
        print(f"   Username: {coachee_username}")
        print(f"   Email: {coachee_email}")
        print(f"   Role: {role}")
        print()
        
        # Generar hash de la nueva contraseña
        password_hash = generate_password_hash(new_password)
        
        # Actualizar contraseña
        cursor.execute("""
            UPDATE user 
            SET password_hash = ? 
            WHERE id = ?
        """, (password_hash, coachee_id))
        
        conn.commit()
        
        print(f"✅ ¡Contraseña actualizada exitosamente!")
        print()
        print(f"{'='*60}")
        print(f"📋 CREDENCIALES DE LOGIN:")
        print(f"{'='*60}")
        print(f"🌐 URL: http://localhost:5002/participant-access")
        print()
        print(f"👤 Username: {coachee_username}")
        print(f"   O usa email: {coachee_email}")
        print(f"🔑 Password: {new_password}")
        print()
        print(f"{'='*60}")
        print(f"✨ Puedes hacer login ahora")
        print(f"{'='*60}\n")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("❌ Uso: python3 reset_coachee_password.py <username_o_email> <nueva_contraseña>")
        print()
        print("Ejemplo:")
        print("   python3 reset_coachee_password.py cristian MiNuevaPassword123")
        print("   python3 reset_coachee_password.py cristian@test.cl MiNuevaPassword123")
        print()
        
        # Mostrar coachees disponibles
        try:
            conn = sqlite3.connect('instance/assessments.db')
            cursor = conn.cursor()
            cursor.execute("SELECT username, email FROM user WHERE role='coachee' LIMIT 10")
            coachees = cursor.fetchall()
            
            if coachees:
                print("📋 Coachees disponibles:")
                for username, email in coachees:
                    print(f"   - {username} ({email})")
            
            conn.close()
        except:
            pass
        
        sys.exit(1)
    
    username = sys.argv[1]
    new_password = sys.argv[2]
    
    reset_coachee_password(username, new_password)
