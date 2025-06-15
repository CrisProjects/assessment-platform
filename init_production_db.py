#!/usr/bin/env python3
"""
Script para inicializar la base de datos en producción
"""

from app_complete import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_production_db():
    """Inicializar la base de datos en producción con usuarios de prueba"""
    try:
        with app.app_context():
            # Crear todas las tablas
            db.create_all()
            print("✅ Tablas creadas correctamente")
            
            # Verificar si ya existen usuarios
            existing_users = User.query.count()
            if existing_users > 0:
                print(f"⚠️ Ya existen {existing_users} usuarios en la base de datos")
                return True
            
            # Crear usuarios de prueba
            users_to_create = [
                {
                    'username': 'admin',
                    'email': 'admin@demo.com',
                    'password': 'admin123',
                    'full_name': 'Administrador del Sistema',
                    'role': 'platform_admin'
                },
                {
                    'username': 'coach_demo',
                    'email': 'coach@demo.com',
                    'password': 'coach123',
                    'full_name': 'Coach de Demostración',
                    'role': 'coach'
                },
                {
                    'username': 'coachee_demo',
                    'email': 'coachee@demo.com',
                    'password': 'coachee123',
                    'full_name': 'Coachee de Demostración',
                    'role': 'coachee',
                    'coach_id': None  # Se asignará después
                }
            ]
            
            created_users = {}
            
            for user_data in users_to_create:
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    password_hash=generate_password_hash(user_data['password']),
                    full_name=user_data['full_name'],
                    role=user_data['role'],
                    is_active=True,
                    created_at=datetime.utcnow()
                )
                
                db.session.add(user)
                created_users[user_data['username']] = user
                print(f"✅ Usuario creado: {user_data['username']} ({user_data['role']})")
            
            # Flush para obtener IDs
            db.session.flush()
            
            # Asignar coach al coachee
            if 'coachee_demo' in created_users and 'coach_demo' in created_users:
                created_users['coachee_demo'].coach_id = created_users['coach_demo'].id
                print("✅ Coachee asignado al coach")
            
            # Commit final
            db.session.commit()
            
            print(f"✅ Base de datos inicializada con {len(created_users)} usuarios")
            
            # Mostrar credenciales
            print("\n" + "="*50)
            print("CREDENCIALES DE ACCESO:")
            print("="*50)
            for user_data in users_to_create:
                print(f"👤 {user_data['role'].upper()}")
                print(f"   Usuario: {user_data['username']}")
                print(f"   Contraseña: {user_data['password']}")
                print(f"   Email: {user_data['email']}")
                print()
            
            return True
            
    except Exception as e:
        print(f"❌ Error inicializando la base de datos: {e}")
        db.session.rollback()
        return False

if __name__ == '__main__':
    success = init_production_db()
    if success:
        print("🎉 Inicialización completada exitosamente")
    else:
        print("💥 Error en la inicialización")
