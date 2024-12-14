from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import os

# Create a new Flask app instance for database setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

def setup_database():
    # Create database file if it doesn't exist
    if not os.path.exists('instance'):
        os.makedirs('instance')
    
    # Create all tables
    with app.app_context():
        db.create_all()
        
        # Add admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            
        # Add test user if it doesn't exist
        user = User.query.filter_by(username='user').first()
        if not user:
            user = User(
                username='user',
                password_hash=generate_password_hash('user123'),
                is_admin=False
            )
            db.session.add(user)
            
        db.session.commit()
        print("Database initialized successfully!")
        print("Admin credentials: admin/admin123")
        print("User credentials: user/user123")

if __name__ == '__main__':
    setup_database()
