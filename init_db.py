from app import app, db, User
from werkzeug.security import generate_password_hash
import sys

def init_db():
    try:
        with app.app_context():
            # Crear tablas
            db.create_all()
            print("Database tables created!")

            changes = False

            # Verificar si el usuario admin ya existe
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    password=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                print("Admin user created.")
                changes = True

            # Verificar si el usuario de prueba ya existe
            test_user = User.query.filter_by(username='user').first()
            if not test_user:
                test_user = User(
                    username='user',
                    password=generate_password_hash('user123'),
                    is_admin=False
                )
                db.session.add(test_user)
                print("Test user created.")
                changes = True

            # Guardar los cambios solo si hubo cambios
            if changes:
                db.session.commit()
                print("Database initialized with default users!")
            else:
                print("No changes made. Users already exist.")

    except Exception as e:
        print(f"Error initializing the database: {e}", file=sys.stderr)

# Ejecutar solo si este archivo es llamado directamente
if __name__ == "__main__":
    init_db()