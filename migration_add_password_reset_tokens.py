"""
Script de migración para agregar tabla de tokens de recuperación de contraseña
Ejecutar con: python migration_add_password_reset_tokens.py
"""

import sys
import os

# Agregar el directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, PasswordResetToken
from datetime import datetime

def run_migration():
    """Ejecuta la migración para agregar la tabla password_reset_token"""
    
    with app.app_context():
        try:
            print("🚀 Iniciando migración: Agregar tabla de tokens de recuperación de contraseña...")
            
            # Crear tabla si no existe
            db.create_all()
            
            print("✅ Tabla 'password_reset_token' creada/verificada exitosamente")
            print("\nEstructura de la tabla:")
            print("  - id: Integer (Primary Key)")
            print("  - user_id: Integer (Foreign Key -> user.id)")
            print("  - token: String(100) (Unique, Indexed)")
            print("  - created_at: DateTime (Indexed)")
            print("  - expires_at: DateTime (Indexed)")
            print("  - used: Boolean (Indexed)")
            print("\n✨ Migración completada exitosamente")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Error durante la migración: {str(e)}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)
