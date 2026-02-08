#!/usr/bin/env python3
"""
Script para resetear contraseña de coach en producción (PostgreSQL Railway)
Uso: python3 reset_coach_password_production.py 'DATABASE_URL' 'username' 'nueva_contraseña'
"""

import sys
import psycopg2
from werkzeug.security import generate_password_hash

def reset_coach_password(database_url, username, new_password):
    """Resetear contraseña de un coach en PostgreSQL"""
    
    print(f"\n🔧 Reseteando contraseña para coach: {username}")
    print(f"📝 Nueva contraseña: {new_password}")
    
    try:
        # Conectar a PostgreSQL
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Verificar que el usuario existe y es coach
        cursor.execute("""
            SELECT id, username, email, full_name, role, active
            FROM "user"
            WHERE username = %s
        """, (username,))
        
        user = cursor.fetchone()
        
        if not user:
            print(f"❌ Usuario '{username}' no encontrado")
            conn.close()
            return False
        
        user_id, db_username, email, full_name, role, active = user
        
        print(f"\n👤 Usuario encontrado:")
        print(f"   ID: {user_id}")
        print(f"   Username: {db_username}")
        print(f"   Email: {email}")
        print(f"   Nombre: {full_name}")
        print(f"   Role: {role}")
        print(f"   Active: {active}")
        
        if role != 'coach':
            print(f"\n⚠️  ADVERTENCIA: El usuario tiene role '{role}', no 'coach'")
            response = input("¿Continuar de todas formas? (y/n): ")
            if response.lower() != 'y':
                print("❌ Operación cancelada")
                conn.close()
                return False
        
        # Generar hash de la nueva contraseña
        password_hash = generate_password_hash(new_password)
        
        # Actualizar contraseña
        cursor.execute("""
            UPDATE "user"
            SET password_hash = %s,
                original_password = %s
            WHERE id = %s
        """, (password_hash, new_password, user_id))
        
        conn.commit()
        
        print(f"\n✅ Contraseña actualizada exitosamente para {username}")
        print(f"🔑 Nueva contraseña: {new_password}")
        print(f"📧 Email: {email}")
        
        conn.close()
        return True
        
    except psycopg2.Error as e:
        print(f"\n❌ Error de PostgreSQL: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False

def main():
    if len(sys.argv) < 4:
        print("\n❌ Uso incorrecto")
        print("\n📖 Uso:")
        print("   python3 reset_coach_password_production.py 'DATABASE_URL' 'username' 'nueva_contraseña'")
        print("\n📝 Ejemplo:")
        print("   python3 reset_coach_password_production.py 'postgresql://...' 'Cristian' 'Cristian123'")
        sys.exit(1)
    
    database_url = sys.argv[1]
    username = sys.argv[2]
    new_password = sys.argv[3]
    
    if not database_url.startswith('postgresql://'):
        print("❌ DATABASE_URL debe comenzar con 'postgresql://'")
        sys.exit(1)
    
    success = reset_coach_password(database_url, username, new_password)
    
    if success:
        print("\n🎉 ¡Operación completada exitosamente!")
        print(f"\n🔐 Ahora puedes hacer login con:")
        print(f"   Username: {username}")
        print(f"   Password: {new_password}")
    else:
        print("\n❌ La operación falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
