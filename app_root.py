from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-fixed-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurar CORS para permitir solicitudes desde Vercel
CORS(app, origins=[
    'http://localhost:3000',
    'https://assessment-platform-*.vercel.app',
    'https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app'
], supports_credentials=True)

# Inicialización de extensiones
db = SQLAlchemy(app)

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelos de base de datos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# USER LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Inicializar la base de datos
def init_db():
    with app.app_context():
        db.create_all()
        
        # Crear usuario admin si no existe
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            
            # Crear evaluación de asertividad en español
            assessment = Assessment(
                title='Evaluación de Asertividad',
                description='Evaluación para medir el nivel de asertividad en diferentes situaciones',
                creator_id=admin_user.id
            )
            db.session.add(assessment)
            db.session.commit()

# Rutas básicas
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Plataforma de Evaluación de Asertividad</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="text-center">
                <h1>Plataforma de Evaluación de Asertividad</h1>
                <p class="lead">Bienvenido a nuestra plataforma de evaluación</p>
                <a href="/login" class="btn btn-primary">Iniciar Sesión</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return 'Usuario o contraseña incorrectos', 400
    
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Iniciar Sesión</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                            <h2 class="card-title text-center mb-4">Iniciar Sesión</h2>
                            <form method="POST">
                                <div class="mb-3">
                                    <label for="username" class="form-label">Usuario</label>
                                    <input type="text" class="form-control" id="username" name="username" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Contraseña</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-primary">Iniciar Sesión</button>
                                </div>
                            </form>
                            <div class="text-center mt-3">
                                <p><strong>Credenciales de prueba:</strong></p>
                                <p>Usuario: admin | Contraseña: admin123</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    assessments = Assessment.query.all()
    return f'''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Panel de Control</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Panel de Control</h2>
                <a href="/logout" class="btn btn-outline-danger">Cerrar Sesión</a>
            </div>
            <div class="alert alert-success">
                <h4>¡Bienvenido, {current_user.username}!</h4>
                <p>Has iniciado sesión correctamente en la Plataforma de Evaluación de Asertividad.</p>
            </div>
            <div class="row">
                {"".join([f'<div class="col-md-6 mb-4"><div class="card"><div class="card-body"><h5 class="card-title">{assessment.title}</h5><p class="card-text">{assessment.description}</p></div></div></div>' for assessment in assessments])}
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# API Routes for React frontend
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json() if request.is_json else None
        
        # Support both JSON and form data
        if data:
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        
        if not username or not password:
            return jsonify({
                'success': False, 
                'error': 'Usuario y contraseña son requeridos'
            }), 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return jsonify({
                'success': True,
                'user': {
                    'username': user.username,
                    'is_admin': user.is_admin
                },
                'message': 'Login exitoso'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Usuario o contraseña incorrectos'
            }), 401
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    try:
        logout_user()
        return jsonify({
            'success': True,
            'message': 'Logout exitoso'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/assessments')
@login_required
def api_assessments():
    assessments = Assessment.query.all()
    assessments_data = []
    for assessment in assessments:
        assessments_data.append({
            'id': assessment.id,
            'title': assessment.title,
            'description': assessment.description,
            'questions': 20,  # Default number of questions for assertiveness assessment
            'created_at': assessment.created_at.isoformat() if assessment.created_at else None
        })
    return jsonify({'assessments': assessments_data})

@app.route('/api/assessment/<int:assessment_id>/save', methods=['POST'])
@login_required
def api_save_assessment(assessment_id):
    try:
        data = request.get_json()
        # For now, just return success - you can implement actual saving logic later
        return jsonify({
            'success': True,
            'message': 'Progreso guardado exitosamente'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/results')
@login_required
def api_results():
    try:
        participant = request.args.get('participant', 'all')
        # Return mock results for now - you can implement actual results logic later
        results_data = {
            'completed': [],
            'in_progress': [],
            'message': 'No hay resultados disponibles aún'
        }
        return jsonify(results_data)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

# Inicializar la base de datos
if __name__ != '__main__':
    init_db()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
