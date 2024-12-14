from app import db, User
from werkzeug.security import generate_password_hash

def init_db():
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        
    # Add a regular test user
    test_user = User.query.filter_by(username='user').first()
    if not test_user:
        test_user = User(
            username='user',
            password_hash=generate_password_hash('user123'),
            is_admin=False
        )
        db.session.add(test_user)
    
    db.session.commit()
    print("Database initialized with default users!")

if __name__ == '__main__':
    init_db()
