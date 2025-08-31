#!/usr/bin/env python3
"""
Script para crear usuarios iniciales en Railway
"""
import os
import sys

def create_initial_users():
    """Crea usuarios iniciales: admin, coach y coachee"""
    try:
        # Agregar el directorio actual al path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        from app import app, db, User
        
        with app.app_context():
            # Crear las tablas si no existen
            db.create_all()
            
            # 1. CREAR ADMIN
            admin_user = User.query.filter_by(username='admin', role='platform_admin').first()
            if admin_user:
                print("🔄 Admin existe, actualizando contraseña...")
                admin_user.set_password('admin123')
                admin_user.is_active = True
                db.session.commit()
                print("✅ Admin actualizado correctamente")
            else:
                print("👤 Creando nuevo usuario admin...")
                admin_user = User(
                    username='admin',
                    email='admin@assessment.com',
                    full_name='Platform Administrator',
                    role='platform_admin',
                    is_active=True
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin creado correctamente")
            
            # 2. CREAR COACH
            coach_user = User.query.filter_by(username='coach', role='coach').first()
            if coach_user:
                print("🔄 Coach existe, actualizando contraseña...")
                coach_user.set_password('coach123')
                coach_user.is_active = True
                db.session.commit()
                print("✅ Coach actualizado correctamente")
            else:
                print("👨‍💼 Creando nuevo usuario coach...")
                coach_user = User(
                    username='coach',
                    email='coach@assessment.com',
                    full_name='Coach Principal',
                    role='coach',
                    is_active=True
                )
                coach_user.set_password('coach123')
                db.session.add(coach_user)
                db.session.commit()
                print("✅ Coach creado correctamente")
            
            # 3. CREAR COACHEE
            coachee_user = User.query.filter_by(username='coachee', role='coachee').first()
            if coachee_user:
                print("🔄 Coachee existe, actualizando contraseña...")
                coachee_user.set_password('coachee123')
                coachee_user.is_active = True
                if not coachee_user.coach_id and coach_user:
                    coachee_user.coach_id = coach_user.id
                db.session.commit()
                print("✅ Coachee actualizado correctamente")
            else:
                print("� Creando nuevo usuario coachee...")
                coachee_user = User(
                    username='coachee',
                    email='coachee@assessment.com',
                    full_name='Coachee de Prueba',
                    role='coachee',
                    is_active=True,
                    coach_id=coach_user.id
                )
                coachee_user.set_password('coachee123')
                db.session.add(coachee_user)
                db.session.commit()
                print("✅ Coachee creado correctamente")
            
            # VERIFICAR CREDENCIALES
            print("\n� Verificando credenciales:")
            
            if admin_user.check_password('admin123'):
                print(f"✅ Admin - Usuario: admin | Contraseña: admin123")
            else:
                print("❌ Error en verificación de admin")
                
            if coach_user.check_password('coach123'):
                print(f"✅ Coach - Usuario: coach | Contraseña: coach123")
            else:
                print("❌ Error en verificación de coach")
                
            if coachee_user.check_password('coachee123'):
                print(f"✅ Coachee - Usuario: coachee | Contraseña: coachee123")
            else:
                print("❌ Error en verificación de coachee")
                
            return True
                
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Inicializando usuarios de la plataforma...")
    success = create_initial_users()
    print("🏁 Proceso completado")
    sys.exit(0 if success else 1)
