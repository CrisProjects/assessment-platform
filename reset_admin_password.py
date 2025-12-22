#!/usr/bin/env python3
"""
Script para resetear la contraseña del admin
"""

import sqlite3
from werkzeug.security import generate_password_hash

def reset_admin_password(new_password):
    """Resetea la contraseña del admin"""
    
    try:
        # Conectar a la base de datos
        conn = sqlite3.connect('instance/assessments.db')
        cursor = conn.cursor()
        
        print(f"\n{'='*60}")
        print(f"🔐 Reseteando contraseña para admin")
        print(f"{'='*60}\n")
        
        # Buscar admin
        cursor.execute("""
            SELECT id, username, email, role
            FROM user
            WHERE username = 'admin'
        """)
        
        admin = cursor.fetchone()
        
        if not admin:
            print(f"❌ Usuario admin no encontrado")
            return False
        
        admin_id, admin_username, admin_email, role = admin
        
        print(f"✅ Admin encontrado:")
        print(f"   ID: {admin_id}")
        print(f"   Username: {admin_username}")
        print(f"   Email: {admin_email}")
        print(f"   Role: {role}")
        print()
        
        # Generar hash de la nueva contraseña
        password_hash = generate_password_hash(new_password)
        
        # Actualizar contraseña
        cursor.execute("""
            UPDATE user 
            SET password_hash = ? 
            WHERE id = ?
        """, (password_hash, admin_id))
        
        conn.commit()
        
        print(f"✅ ¡Contraseña actualizada exitosamente!")
        print()
        print(f"{'='*60}")
        print(f"📋 CREDENCIALES DE LOGIN:")
        print(f"{'='*60}")
        print(f"🌐 URL: http://localhost:5002/admin-login")
        print()
        print(f"👤 Username: admin")
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
    import sys
    
    if len(sys.argv) < 2:
        print("❌ Uso: python3 reset_admin_password.py <nueva_contraseña>")
        print()
        print("Ejemplo:")
        print("   python3 reset_admin_password.py Admin123456")
        sys.exit(1)
    
    new_password = sys.argv[1]
    
    if len(new_password) < 8:
        print("❌ La contraseña debe tener al menos 8 caracteres")
        sys.exit(1)
    
    reset_admin_password(new_password)
