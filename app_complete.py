#!/usr/bin/env python3
"""
Aplicación Flask completa con frontend y backend integrados
Perfecta para desplegar en Render como un solo servicio
FIXED: Botón 'Iniciar Evaluación' - Endpoint /api/register actualizado
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from datetime import datetime
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func
from coach_analysis import (
    calculate_dimensional_scores_from_responses,
    get_assessment_strengths,
    get_assessment_improvements,
    get_coach_recommendations,
    calculate_progress_trend
)

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-fixed-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurar CORS - Incluir Vercel y Render
CORS(app, 
     origins=[
         'http://localhost:3000',
         'https://assessment-platform-1nuo.onrender.com',  # Render backend (para auto-requests)
         'https://assessment-platform-final.vercel.app',  # URL PRINCIPAL de Vercel ✅
         'https://assessment-platform-deploy.vercel.app',  # NUEVA URL DE DEPLOY ✅
         'https://assessment-platform-final-o6uoi0a9a-cris-projects-92f3df55.vercel.app',  # URLs de preview
         'https://assessment-platform-final-nkfv3eieh-cris-projects-92f3df55.vercel.app',
         'https://assessment-platform-final-e7ygyztfi-cris-projects-92f3df55.vercel.app',
         'https://assessment-platform-4h58ggw5n-cris-projects-92f3df55.vercel.app',  # URLs anteriores
         'https://assessment-platform-g18jyp9wv-cris-projects-92f3df55.vercel.app',
         'https://assessment-platform-lg8l1boz6-cris-projects-92f3df55.vercel.app',
         'https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app'
     ], 
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Origin', 'Accept'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

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
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    
    # Sistema de roles de 3 niveles
    role = db.Column(db.String(20), default='coachee')  # 'platform_admin', 'coach', 'coachee'
    is_active = db.Column(db.Boolean, default=True)
    
    # Relación coach-coachee
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relaciones
    coach = db.relationship('User', remote_side=[id], backref='coachees')
    assessments = db.relationship('AssessmentResult', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_platform_admin(self):
        return self.role == 'platform_admin'
    
    @property
    def is_coach(self):
        return self.role == 'coach'
    
    @property
    def is_coachee(self):
        return self.role == 'coachee'

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), default='multiple_choice')
    options = db.Column(db.JSON)
    correct_answer = db.Column(db.Integer)

class AssessmentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    score = db.Column(db.Float)
    total_questions = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    result_text = db.Column(db.Text)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_option = db.Column(db.Integer)
    assessment_result_id = db.Column(db.Integer, db.ForeignKey('assessment_result.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decoradores para control de acceso por roles
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                # Para vistas HTML, redirigir al login
                if request.accept_mimetypes.accept_html:
                    flash('Por favor inicia sesión para continuar')
                    return redirect(url_for('login'))
                else:
                    return jsonify({'error': 'Autenticación requerida'}), 401
            
            if required_role == 'platform_admin' and not current_user.is_platform_admin:
                if request.accept_mimetypes.accept_html:
                    flash('Acceso denegado: Se requieren permisos de administrador de plataforma')
                    dashboard_url = get_dashboard_url(current_user.role)
                    return redirect(dashboard_url)
                else:
                    return jsonify({'error': 'Acceso denegado: Se requieren permisos de administrador de plataforma'}), 403
            elif required_role == 'coach' and not (current_user.is_coach or current_user.is_platform_admin):
                if request.accept_mimetypes.accept_html:
                    flash('Acceso denegado: Se requieren permisos de coach')
                    dashboard_url = get_dashboard_url(current_user.role)
                    return redirect(dashboard_url)
                else:
                    return jsonify({'error': 'Acceso denegado: Se requieren permisos de coach'}), 403
            elif required_role == 'coachee' and not current_user.is_active:
                if request.accept_mimetypes.accept_html:
                    flash('Cuenta desactivada')
                    return redirect(url_for('login'))
                else:
                    return jsonify({'error': 'Cuenta desactivada'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def coach_access_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_coach or current_user.is_platform_admin):
            return jsonify({'error': 'Acceso denegado: Se requieren permisos de coach o superior'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Función helper para verificar acceso a datos de coachee
def can_access_coachee_data(target_user_id):
    if current_user.is_platform_admin:
        return True
    elif current_user.is_coach:
        # Coach puede acceder a datos de sus coachees
        target_user = User.query.get(target_user_id)
        return target_user and target_user.coach_id == current_user.id
    elif current_user.is_coachee:
        # Coachee solo puede acceder a sus propios datos
        return current_user.id == target_user_id
    return False

# Rutas del Frontend
@app.route('/favicon.ico')
def favicon():
    return '', 204

# ========================
# RUTAS DE AUTENTICACIÓN
# ========================

# API Routes
@app.route('/api/login', methods=['POST'])
def api_login():
    """Login API para autenticación de usuarios"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        # Buscar usuario por username o email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'full_name': user.full_name,
                    'email': user.email,
                    'role': user.role,
                    'coach_id': user.coach_id
                },
                'redirect_url': get_dashboard_url(user.role)
            }), 200
        else:
            return jsonify({'error': 'Credenciales inválidas o cuenta desactivada'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    """Logout API"""
    logout_user()
    return jsonify({'success': True, 'message': 'Sesión cerrada exitosamente'}), 200

@app.route('/api/register', methods=['POST'])
def api_register():
    """Registro de nuevos usuarios (solo coachees por defecto)"""
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['username', 'email', 'password', 'full_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Verificar si el usuario ya existe
        if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
            return jsonify({'error': 'Usuario o email ya registrado'}), 400
        
        # Crear nuevo usuario (coachee por defecto)
        new_user = User(
            username=data['username'],
            email=data['email'],
            full_name=data['full_name'],
            role='coachee'
        )
        new_user.set_password(data['password'])
        
        # Si se especifica un coach
        if data.get('coach_id'):
            coach = User.query.filter_by(id=data['coach_id'], role='coach').first()
            if coach:
                new_user.coach_id = coach.id
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Usuario registrado exitosamente',
            'user_id': new_user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error en registro: {str(e)}'}), 500

def get_dashboard_url(role):
    """Retorna la URL del dashboard según el rol"""
    if role == 'platform_admin':
        return '/platform-admin-dashboard'
    elif role == 'coach':
        return '/coach-dashboard'
    else:
        return '/coachee-dashboard'

@app.route('/api/assessments', methods=['GET'])
@login_required
def api_get_assessments():
    assessments = Assessment.query.all()
    assessments_data = []
    
    for assessment in assessments:
        questions = Question.query.filter_by(assessment_id=assessment.id).all()
        questions_data = []
        
        for question in questions:
            questions_data.append({
                'id': question.id,
                'content': question.content,
                'question_type': question.question_type,
                'options': question.options
            })
        
        assessments_data.append({
            'id': assessment.id,
            'title': assessment.title,
            'description': assessment.description,
            'created_at': assessment.created_at.isoformat(),
            'questions': questions_data
        })
    
    return jsonify({'assessments': assessments_data})

@app.route('/api/questions', methods=['GET'])
def api_get_questions():
    """Endpoint para obtener todas las preguntas de la evaluación de asertividad - SIN autenticación requerida"""
    try:
        print(f"[DEBUG] Questions endpoint called")
        
        # Obtener la primera evaluación (evaluación de asertividad)
        assessment = Assessment.query.first()
        if not assessment:
            print(f"[DEBUG] No assessment found")
            return jsonify({'error': 'No se encontró la evaluación'}), 404
        
        print(f"[DEBUG] Assessment found: {assessment.title}")
        
        questions = Question.query.filter_by(assessment_id=assessment.id).all()
        print(f"[DEBUG] Questions found: {len(questions)}")
        
        questions_data = []
        
        for question in questions:
            questions_data.append({
                'id': question.id,
                'content': question.content,
                'question_type': question.question_type,
                'options': question.options
            })
        
        print(f"[DEBUG] Returning {len(questions_data)} questions")
        return jsonify({'questions': questions_data})
        
    except Exception as e:
        print(f"[ERROR] Questions endpoint error: {e}")
        return jsonify({
            'error': f'Error interno del servidor: {str(e)}'
        }, 500)

@app.route('/api/save_assessment', methods=['POST'])
@login_required
def api_save_assessment():
    """Guardar evaluación de asertividad con análisis dimensional"""
    try:
        data = request.get_json()
        
        # Datos demográficos
        age = data.get('age')
        gender = data.get('gender')
        answers = data.get('answers', {})
        
        # Validar datos
        if not answers:
            return jsonify({'error': 'No se recibieron respuestas'}), 400
        
        # Calcular dimensiones usando la misma lógica del frontend
        dimensional_scores = calculate_dimensional_scores_backend(answers)
        
        # Calcular puntuación total
        total_score = sum(dimensional_scores.values()) / len(dimensional_scores)
        
        # Determinar nivel de asertividad
        assertiveness_level = get_assertiveness_level(total_score)
        
        # Crear resultado de evaluación
        assessment_result = AssessmentResult(
            user_id=current_user.id,
            assessment_id=1,  # Asumiendo que tenemos una evaluación con ID 1
            score=total_score,
            total_questions=len(answers),
            result_text=f"Nivel: {assertiveness_level}, Puntuaciones: {dimensional_scores}"
        )
        
        db.session.add(assessment_result)
        db.session.flush()  # Flush to get the ID without committing
        
        # Guardar respuestas individuales para análisis detallado
        for question_index, answer in answers.items():
            response = Response(
                user_id=current_user.id,
                question_id=int(question_index) + 1,  # Asumiendo IDs secuenciales
                selected_option=answer,
                assessment_result_id=assessment_result.id
            )
            db.session.add(response)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'result_id': assessment_result.id,
            'total_score': int(total_score),
            'assertiveness_level': assertiveness_level,
            'dimensional_scores': dimensional_scores,
            'message': 'Evaluación guardada exitosamente'
        }, 200)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error guardando evaluación: {str(e)}'}), 500

def calculate_dimensional_scores_backend(answers):
    """Calcular puntuaciones dimensionales (backend)"""
    # Mapeo de preguntas a dimensiones (misma lógica que frontend)
    question_to_dimension = {
        0: 'conflictos',       # Pregunta 1
        1: 'derechos',         # Pregunta 2
        2: 'opiniones',        # Pregunta 3
        3: 'derechos',         # Pregunta 4
        4: 'comunicacion',     # Pregunta 5
        5: 'comunicacion',     # Pregunta 6
        6: 'autoconfianza',    # Pregunta 7
        7: 'conflictos',       # Pregunta 8
        8: 'conflictos',       # Pregunta 9
        9: 'autoconfianza'     # Pregunta 10
    }
    
    dimension_scores = {
        'comunicacion': [],
        'derechos': [],
        'opiniones': [],
        'conflictos': [],
        'autoconfianza': []
    }
    
    # Agrupar respuestas por dimensión
    for question_index, answer in answers.items():
        dimension = question_to_dimension.get(int(question_index))
        if dimension:
            # Convertir respuesta a puntuación
            points = 4  # Asertiva por defecto
            if answer == 1:
                points = 1  # Pasiva
            elif answer == 2:
                points = 2  # Agresiva
            elif answer == 3:
                points = 3  # Mixta
            
            dimension_scores[dimension].append(points)
    
    # Calcular promedios y convertir a escala 0-100
    final_scores = {}
    for dimension, scores in dimension_scores.items():
        if scores:
            avg_score = sum(scores) / len(scores)
            final_scores[dimension] = round((avg_score / 4) * 100, 1)
        else:
            # Si no hay preguntas para esta dimensión, usar promedio general
            all_scores = [score for scores_list in dimension_scores.values() for score in scores_list]
            if all_scores:
                general_avg = sum(all_scores) / len(all_scores)
                final_scores[dimension] = round((general_avg / 4) * 100, 1)
            else:
                final_scores[dimension] = 50.0  # Valor neutral por defecto
    
    return final_scores

def get_assertiveness_level(score):
    """Determinar nivel de asertividad basado en puntuación"""
    if score >= 80:
        return "Muy Asertivo"
    elif score >= 60:
        return "Asertivo"
    elif score >= 40:
        return "Moderadamente Asertivo"
    else:
        return "Poco Asertivo"

@app.route('/api/submit', methods=['POST'])
@login_required
def api_submit_assessment():
    """Alias para /api/save_assessment - endpoint para enviar respuestas de evaluación"""
    return api_save_assessment()

@app.route('/api/deployment-test', methods=['GET'])
def api_deployment_test():
    """Endpoint simple para verificar que el deployment está funcionando"""
    return jsonify({
        'status': 'success',
        'message': 'New deployment is working!',
        'timestamp': datetime.utcnow().isoformat(),
        'version': 'force-redeploy-1749431299'
    })

@app.route('/api/init-db', methods=['POST', 'GET'])
def api_init_database():
    """Endpoint para inicializar la base de datos con datos de muestra"""
    try:
        result = init_database()
        
        # Debug: Check what type result is
        print(f"DEBUG: init_database() returned: {result}, type: {type(result)}")
        
        # Force result to be a simple boolean - this should definitely be JSON serializable
        result = bool(result) if result is not None else True
        
        # Verificar que el usuario admin existe with proper error handling
        try:
            admin_user = User.query.filter_by(username='admin').first()
            admin_exists = admin_user is not None
            user_count = User.query.count()
        except Exception as db_error:
            print(f"DEBUG: Database query error: {db_error}")
            admin_exists = False
            user_count = 0
        
        # Create response data with only basic types
        response_data = {
            'status': 'success',
            'message': 'Base de datos verificada/inicializada correctamente',
            'admin_exists': bool(admin_exists),
            'user_count': int(user_count),
            'initialization_result': bool(result),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(response_data)
    except Exception as e:
        print(f"DEBUG: Full error in api_init_database: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error inicializando base de datos: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/health', methods=['GET'])
def api_health():
    """Endpoint de salud para verificar que el API está funcionando"""
    try:
        # Verificar conexión a base de datos
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'message': 'API funcionando correctamente',
            'database': 'connected'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'message': 'Error en la conexión a base de datos',
            'error': str(e)
        }), 500

@app.route('/health')
@app.route('/status')
def simple_health():
    """Endpoint de salud simple para Render"""
    return jsonify({
        'status': 'ok',
        'message': 'Assessment Platform is running',
        'timestamp': datetime.utcnow().isoformat()
    })

def init_database():
    """Inicializar la base de datos con datos de muestra"""
    try:
        print("DEBUG: Starting MINIMAL init_database()")
        
        with app.app_context():
            print("DEBUG: Creating tables only")
            db.create_all()
            
        print("DEBUG: Returning True from minimal init_database()")
        return True
        
    except Exception as e:
        print(f"❌ Error inicializando base de datos: {e}")
        return False

# ========================
# FUNCIONES DE INICIALIZACIÓN
# ========================

def create_default_users():
    """Crear usuarios por defecto del sistema"""
    try:
        # Administrador de plataforma
        platform_admin = User.query.filter_by(username='platform_admin').first()
        if not platform_admin:
            platform_admin = User(
                username='platform_admin',
                email='admin@assessment-platform.com',
                full_name='Administrador de Plataforma',
                role='platform_admin'
            )
            platform_admin.set_password('admin123')  # Cambiar en producción
            db.session.add(platform_admin)
            print("✅ Administrador de plataforma creado")
        
        # Crear usuario admin como alias para compatibilidad
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@assessment-platform.com',
                full_name='Administrador',
                role='platform_admin'
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            print("✅ Usuario admin (alias) creado")
        
        # Coach de ejemplo
        coach = User.query.filter_by(username='coach_demo').first()
        if not coach:
            coach = User(
                username='coach_demo',
                email='coach@assessment-platform.com',
                full_name='Coach Demo',
                role='coach'
            )
            coach.set_password('coach123')  # Cambiar en producción
            db.session.add(coach)
            db.session.commit()  # Commit para obtener el ID
            print("✅ Coach demo creado")
        
        # Coachee de ejemplo
        coachee = User.query.filter_by(username='coachee_demo').first()
        if not coachee:
            coachee = User(
                username='coachee_demo',
                email='coachee@assessment-platform.com',
                full_name='Coachee Demo',
                role='coachee',
                coach_id=coach.id if coach else None
            )
            coachee.set_password('coachee123')  # Cambiar en producción
            db.session.add(coachee)
            print("✅ Coachee demo creado")
        
        db.session.commit()
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creando usuarios por defecto: {e}")
        return False

# Inicializar la base de datos automáticamente cuando la aplicación arranque
# COMENTADO para evitar problemas en producción - se inicializa en wsgi_production.py
# with app.app_context():
#     try:
#         # Siempre crear las tablas
#         db.create_all()
#         
#         # Verificar/crear usuario admin
#         admin_user = User.query.filter_by(username='admin').first()
#         if not admin_user:
#             print("🔧 Creando usuario admin de emergencia...")
#             admin_user = User(
#                 username='admin',
#                 email='admin@platform.com',
#                 full_name='Platform Administrator',
#                 role='platform_admin'
#             )
#             admin_user.set_password('admin123')
#             db.session.add(admin_user)
#             db.session.commit()
#             print("✅ Usuario admin creado exitosamente")
#         
#         # Ejecutar inicialización completa
#         init_database()
#         create_default_users()
#     except Exception as e:
#         print(f"⚠️ No se pudo inicializar la base de datos automáticamente: {e}")
#         # Crear usuario de emergencia sin depender de init_database
#         try:
#             db.create_all()
#             if not User.query.filter_by(username='admin').first():
#                 admin_user = User(
#                     username='admin',
#                     email='admin@platform.com', 
#                     full_name='Platform Administrator',
#                     role='platform_admin'
#                 )
#                 admin_user.set_password('admin123')
#                 db.session.add(admin_user)
#                 db.session.commit()
#                 print("✅ Usuario admin de emergencia creado")
#         except Exception as emergency_error:
#             print(f"❌ Error crítico creando usuario de emergencia: {emergency_error}")

@app.route('/api/demographics', methods=['POST'])
def api_demographics():
    """Endpoint específico para registrar datos demográficos - SIN autenticación requerida"""
    try:
        data = request.get_json()
        
        name = data.get('name')
        email = data.get('email')
        age = data.get('age')
        gender = data.get('gender')
        
        print(f"[DEBUG] Demographics data received: name={name}, email={email}, age={age}, gender={gender}")
        
        if not all([name, email, age, gender]):
            missing_fields = [field for field, value in [('name', name), ('email', email), ('age', age), ('gender', gender)] if not value]
            return jsonify({
                'success': False, 
                'error': f'Campos faltantes: {", ".join(missing_fields)}'
            }), 400
        
        # Almacenar en la sesión para la evaluación
        session['participant_data'] = {
            'name': name,
            'email': email,
            'age': age,
            'gender': gender
        }
        
        print(f"[DEBUG] Session data stored: {session.get('participant_data')}")
        
        return jsonify({
            'success': True,
            'message': 'Datos demográficos registrados exitosamente',
            'user': {
                'id': 1,  # ID fijo para admin
                'username': 'admin',
                'role': 'platform_admin',
                'participant_data': session['participant_data']
            }
        })
        
    except Exception as e:
        print(f"[ERROR] Demographics endpoint error: {e}")
        return jsonify({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }), 500

@app.route('/api/debug-questions', methods=['GET'])
def debug_questions():
    """Endpoint de debugging para diagnosticar el problema con questions"""
    try:
        result = {}
        
        # Test 1: Count assessments
        assessment_count = Assessment.query.count()
        result['assessment_count'] = assessment_count
        
        # Test 2: Get first assessment
        assessment = Assessment.query.first()
        if assessment:
            result['assessment'] = {
                'id': assessment.id,
                'title': assessment.title,
                'description': assessment.description
            }
            
            # Test 3: Count questions for this assessment
            question_count = Question.query.filter_by(assessment_id=assessment.id).count()
            result['question_count'] = question_count
            
            # Test 4: Get first question
            first_question = Question.query.filter_by(assessment_id=assessment.id).first()
            if first_question:
                result['first_question'] = {
                    'id': first_question.id,
                    'content': first_question.content[:100] if first_question.content else None,
                    'question_type': first_question.question_type,
                    'options_type': type(first_question.options).__name__,
                    'options_length': len(first_question.options) if first_question.options else 0
                }
        else:
            result['assessment'] = None
            
        return jsonify({
            'status': 'success',
            'debug_info': result
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        }), 500

@app.route('/api/cors-test', methods=['GET', 'OPTIONS'])
def cors_test():
    """Endpoint para verificar configuración CORS"""
    return jsonify({
        'status': 'CORS working',
        'timestamp': datetime.utcnow().isoformat(),
        'origin': request.headers.get('Origin'),
        'user_agent': request.headers.get('User-Agent'),
        'vercel_deploy_url_configured': 'https://assessment-platform-deploy.vercel.app' in app.config.get('allowed_origins', [])
    })

# ========================
# RUTAS DE DASHBOARDS
# ========================

@app.route('/platform-admin-dashboard')
@role_required('platform_admin')
def platform_admin_dashboard():
    """Dashboard para administrador de plataforma"""
    return render_template('admin_dashboard.html')

@app.route('/coach-dashboard')
@coach_access_required
def coach_dashboard():
    """Dashboard para coaches"""
    try:
        # Obtener estadísticas básicas del coach
        coach_id = current_user.id
        
        # Contar coachees asignados
        total_coachees = User.query.filter_by(coach_id=coach_id, role='coachee').count()
        
        # Contar evaluaciones completadas por los coachees
        coachees = User.query.filter_by(coach_id=coach_id, role='coachee').all()
        coachee_ids = [c.id for c in coachees]
        
        total_assessments = 0
        if coachee_ids:
            total_assessments = AssessmentResult.query.filter(AssessmentResult.user_id.in_(coachee_ids)).count()
        
        # Crear estadísticas simples para el template
        stats = {
            'total_coachees': total_coachees,
            'total_assessments': total_assessments
        }
        
        return render_template('coach_dashboard.html', stats=stats)
    except Exception as e:
        print(f"Error en coach_dashboard: {e}")
        # Retornar template básico en caso de error
        return render_template('coach_dashboard.html', stats={'total_coachees': 0, 'total_assessments': 0})

@app.route('/coachee-dashboard')
@login_required
def coachee_dashboard():
    """Dashboard para coachees"""
    if not current_user.is_coachee:
        return redirect(get_dashboard_url(current_user.role))
    return render_template('coachee_dashboard.html')

# ========================
# APIS PARA DASHBOARDS
# ========================

@app.route('/api/admin/platform-stats', methods=['GET'])
@role_required('platform_admin')
def get_platform_stats():
    """Estadísticas generales de la plataforma"""
    try:
        stats = {
            'total_users': User.query.count(),
            'total_coaches': User.query.filter_by(role='coach').count(),
            'total_coachees': User.query.filter_by(role='coachee').count(),
            'total_assessments': AssessmentResult.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'recent_assessments': AssessmentResult.query.filter(
                AssessmentResult.completed_at >= datetime.utcnow().replace(day=1)
            ).count()
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users', methods=['GET'])
@role_required('platform_admin')
def get_all_users():
    """Obtener lista de todos los usuarios para el dashboard de admin"""
    try:
        users = User.query.all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'coach_id': user.coach_id
            })
        
        return jsonify(users_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/my-coachees', methods=['GET'])
@coach_access_required
def get_my_coachees():
    """Obtener lista de coachees asignados al coach actual"""
    try:
        coach_id = current_user.id
        coachees = User.query.filter_by(coach_id=coach_id, role='coachee').all()
        
        coachees_data = []
        for coachee in coachees:
            # Obtener última evaluación del coachee
            latest_assessment = AssessmentResult.query.filter_by(
                user_id=coachee.id
            ).order_by(AssessmentResult.completed_at.desc()).first()
            
            # Contar total de evaluaciones
            total_assessments = AssessmentResult.query.filter_by(user_id=coachee.id).count()
            
            coachee_data = {
                'id': coachee.id,
                'username': coachee.username,
                'email': coachee.email,
                'full_name': coachee.full_name,
                'created_at': coachee.created_at.isoformat() if coachee.created_at else None,
                'last_login': coachee.last_login.isoformat() if coachee.last_login else None,
                'total_assessments': total_assessments,
                'latest_assessment': None
            }
            
            if latest_assessment:
                coachee_data['latest_assessment'] = {
                    'id': latest_assessment.id,
                    'completed_at': latest_assessment.completed_at.isoformat() if latest_assessment.completed_at else None,
                    'score': latest_assessment.score
                }
            
            coachees_data.append(coachee_data)
        
        return jsonify(coachees_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/coachee-progress/<int:coachee_id>', methods=['GET'])
@coach_access_required
def get_coachee_progress(coachee_id):
    """Obtener progreso histórico de un coachee específico"""
    try:
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id).first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no asignado'}), 404
        
        # Obtener todas las evaluaciones del coachee
        assessments = AssessmentResult.query.filter_by(
            user_id=coachee_id
        ).order_by(AssessmentResult.completed_at.asc()).all()
        
        progress_data = []
        for assessment in assessments:
            progress_data.append({
                'id': assessment.id,
                'completed_at': assessment.completed_at.isoformat() if assessment.completed_at else None,
                'score': assessment.score,
                'result_text': assessment.result_text
            })
        
        return jsonify({
            'coachee': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'email': coachee.email
            },
            'assessments': progress_data
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/dashboard-stats', methods=['GET'])
@coach_access_required
def get_coach_dashboard_stats():
    """Obtener estadísticas del dashboard para el coach actual"""
    try:
        coach_id = current_user.id
        
        # Contar coachees
        total_coachees = User.query.filter_by(coach_id=coach_id, role='coachee').count()
        
        # Obtener IDs de coachees
        coachees = User.query.filter_by(coach_id=coach_id, role='coachee').all()
        coachee_ids = [c.id for c in coachees]
        
        # Estadísticas de evaluaciones
        total_assessments = 0
        completed_assessments = 0
        avg_score = 0
        recent_activity = 0
        
        if coachee_ids:
            # Total de evaluaciones
            total_assessments = AssessmentResult.query.filter(
                AssessmentResult.user_id.in_(coachee_ids)
            ).count()
            
            # Evaluaciones completadas
            completed_assessments = AssessmentResult.query.filter(
                AssessmentResult.user_id.in_(coachee_ids),
                AssessmentResult.completed_at.isnot(None)
            ).count()
            
            # Promedio de puntuación
            results = AssessmentResult.query.filter(
                AssessmentResult.user_id.in_(coachee_ids),
                AssessmentResult.score.isnot(None)
            ).all()
            
            if results:
                avg_score = sum(r.score for r in results) / len(results)
            
            # Actividad reciente (último mes)
            one_month_ago = datetime.utcnow().replace(day=1)
            recent_activity = AssessmentResult.query.filter(
                AssessmentResult.user_id.in_(coachee_ids),
                AssessmentResult.completed_at >= one_month_ago
            ).count()
        
        # Distribución de niveles de asertividad
        score_distribution = {'Poco Asertivo': 0, 'Moderadamente Asertivo': 0, 'Asertivo': 0, 'Muy Asertivo': 0}
        if coachee_ids:
            latest_assessments = db.session.query(
                AssessmentResult.user_id,
                func.max(AssessmentResult.completed_at).label('latest_date')
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids),
                AssessmentResult.score.isnot(None)
            ).group_by(AssessmentResult.user_id).subquery()
            
            latest_results = db.session.query(AssessmentResult).join(
                latest_assessments,
                (AssessmentResult.user_id == latest_assessments.c.user_id) &
                (AssessmentResult.completed_at == latest_assessments.c.latest_date)
            ).all()
            
            for result in latest_results:
                level = get_assertiveness_level(result.score)
                if level in score_distribution:
                    score_distribution[level] += 1
        
        stats = {
            'total_coachees': total_coachees,
            'total_assessments': total_assessments,
            'completed_assessments': completed_assessments,
            'avg_score': round(avg_score, 1),
            'recent_activity': recent_activity,
            'score_distribution': score_distribution
        }
        
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/assign-coachee', methods=['POST'])
@coach_access_required
def assign_coachee():
    """Asignar un coachee al coach actual"""
    try:
        data = request.get_json()
        coachee_username = data.get('coachee_username')
        
        if not coachee_username:
            return jsonify({'error': 'Username del coachee requerido'}), 400
        
        # Buscar el coachee
        coachee = User.query.filter_by(username=coachee_username, role='coachee').first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado'}), 404
        
        # Verificar que no tenga coach asignado
        if coachee.coach_id and coachee.coach_id != current_user.id:
            return jsonify({'error': 'El coachee ya tiene un coach asignado'}), 400
        
        # Asignar coach
        coachee.coach_id = current_user.id
        db.session.commit()
        
        return jsonify({
            'message': 'Coachee asignado exitosamente',
            'coachee': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'email': coachee.email
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500





@app.route('/api/admin/change-user-role', methods=['POST'])
@role_required('platform_admin')
def change_user_role():
    """Cambiar el rol de un usuario - SOLO PARA ADMINISTRADORES"""
    try:
        data = request.get_json()
        username = data.get('username')
        new_role = data.get('role')
        
        if not username or not new_role:
            return jsonify({'error': 'Username y role requeridos'}), 400
        
        # Validar roles permitidos
        allowed_roles = ['coachee', 'coach', 'platform_admin']
        if new_role not in allowed_roles:
            return jsonify({'error': 'Rol no válido'}), 400
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Cambiar rol
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Rol de {username} cambiado de {old_role} a {new_role}',
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'is_platform_admin': user.is_platform_admin
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error cambiando rol: {str(e)}'
        }), 500

@app.route('/api/temp/change-role', methods=['POST'])
def temp_change_role():
    """Endpoint temporal para cambiar roles - SOLO PARA SETUP INICIAL"""
    try:
        data = request.get_json()
        username = data.get('username')
        new_role = data.get('role')
        
        if not username or not new_role:
            return jsonify({'error': 'Username y role requeridos'}), 400
        
        # Validar roles permitidos
        allowed_roles = ['coachee', 'coach', 'platform_admin']
        if new_role not in allowed_roles:
            return jsonify({'error': 'Rol no válido'}), 400
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Cambiar rol
        old_role = user.role
        user.role = new_role
        
        # Si estamos convirtiendo a coachee, asignar coach si se especifica
        coach_id = data.get('coach_id')
        if new_role == 'coachee' and coach_id:
            user.coach_id = coach_id
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Rol de {username} cambiado de {old_role} a {new_role}',
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'coach_id': user.coach_id
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error cambiando rol: {str(e)}'
        }), 500

# ========================
# RUTAS DE PÁGINAS HTML
# ========================

@app.route('/login')
def login_page():
    """Página de login"""
    return render_template('login.html')

@app.route('/')
def index():
    """Página principal - sirve el frontend estático directamente"""
    try:
        # Servir el index.html directamente desde el directorio raíz
        return send_from_directory('.', 'index.html')
    except Exception as e:
        # Fallback: crear página básica si index.html no existe
        return """
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Plataforma de Evaluación de Asertividad</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .container { max-width: 600px; margin: 0 auto; }
                .btn { background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Plataforma de Evaluación de Asertividad</h1>
                <p>Bienvenido a la plataforma de evaluación.</p>
                <a href="/login" class="btn">Ir al Login</a>
            </div>
        </body>
        </html>
        """, 200

@app.route('/api/debug-users', methods=['GET', 'POST'])
def debug_users():
    """Endpoint de debugging para diagnosticar problemas con usuarios"""
    try:
        with app.app_context():
            # Información general
            user_count = User.query.count()
            all_users = User.query.all()
            
            users_info = []
            for user in all_users:
                users_info.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_platform_admin': user.is_platform_admin,
                    'is_active': user.is_active
                })
            
            # Si es POST, intentar crear usuarios manualmente
            if request.method == 'POST':
                print("🔧 Forzando creación manual de usuarios...")
                result = create_default_users()
                
                # Actualizar información después de la creación
                user_count = User.query.count()
                all_users = User.query.all()
                users_info = []
                for user in all_users:
                    users_info.append({
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role,
                        'is_platform_admin': user.is_platform_admin,
                        'is_active': user.is_active
                    })
                    
                return jsonify({
                    'status': 'success',
                    'message': 'Creación manual de usuarios ejecutada',
                    'user_count': user_count,
                    'users': users_info,
                    'creation_result': result,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            return jsonify({
                'status': 'success',
                'message': 'Estado actual de usuarios',
                'user_count': user_count,
                'users': users_info,
                'timestamp': datetime.utcnow().isoformat()
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error en debug de usuarios: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/admin/promote-user', methods=['POST'])
def promote_user_to_admin():
    """Endpoint temporal para promover un usuario a admin - SOLO PARA DEPLOYMENT INICIAL"""
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({'error': 'Username requerido'}), 400
        
        # Solo permitir promover usuarios específicos
        allowed_usernames = ['admin', 'platform_admin']
        if username not in allowed_usernames:
            return jsonify({'error': 'Usuario no autorizado para promoción'}), 403
        
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            # Promover a platform_admin
            user.role = 'platform_admin'
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Usuario {username} promovido a platform_admin',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'role': user.role,
                    'is_platform_admin': user.is_platform_admin
                }
            })
            
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error promoviendo usuario: {str(e)}'
        }), 500

@app.route('/api/init-database', methods=['POST'])
def api_init_database_production():
    """Endpoint para inicializar la base de datos en producción"""
    try:
        # Verificar que no sea un ataque - solo permitir en producción o si viene de localhost
        if request.remote_addr not in ['127.0.0.1', '::1'] and 'render.com' not in request.host:
            return jsonify({'error': 'No autorizado'}), 403
        
        # Crear todas las tablas
        db.create_all()
        print("✅ Todas las tablas creadas")
        
        # Verificar si ya existen usuarios
        existing_users = User.query.count()
        users_created = 0
        
        if existing_users == 0:
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
        
            # Flush para obtener IDs
            db.session.flush()
            
            # Asignar coach al coachee
            if 'coachee_demo' in created_users and 'coach_demo' in created_users:
                created_users['coachee_demo'].coach_id = created_users['coach_demo'].id
                
            users_created = len(created_users)
        else:
            users_created = 0
        
        # Verificar y crear evaluación con preguntas
        questions_created = 0
        existing_assessment = Assessment.query.filter_by(title='Evaluación de Asertividad').first()
        
        if not existing_assessment:
            # Crear la evaluación principal
            assessment = Assessment(
                title='Evaluación de Asertividad',
                description='Evaluación para medir el nivel de asertividad en diferentes dimensiones',
                created_at=datetime.utcnow()
            )
            
            db.session.add(assessment)
            db.session.flush()  # Para obtener el ID
            
            # 10 preguntas básicas de asertividad
            questions_data = [
                'Cuando alguien me critica de manera injusta, expreso mi desacuerdo de forma clara y respetuosa.',
                'Me siento cómodo/a expresando mis opiniones en grupo, incluso si difieren de la mayoría.',
                'Puedo decir "no" cuando alguien me pide algo que no quiero o no puedo hacer.',
                'Cuando necesito ayuda, la pido sin sentirme incómodo/a.',
                'Defiendo mis derechos cuando siento que están siendo violados.',
                'Establezco límites claros en mis relaciones personales.',
                'Abordo los conflictos de frente en lugar de evitarlos.',
                'Mantengo la calma durante las discusiones difíciles.',
                'Confío en mis habilidades y capacidades.',
                'Me siento seguro/a de mis decisiones.'
            ]
            
            # Opciones de respuesta (escala Likert)
            response_options = [
                "Totalmente en desacuerdo",
                "En desacuerdo", 
                "Neutral",
                "De acuerdo",
                "Totalmente de acuerdo"
            ]
            
            # Crear las preguntas
            for content in questions_data:
                question = Question(
                    assessment_id=assessment.id,
                    content=content,
                    question_type='likert',
                    options=response_options
                )
                db.session.add(question)
                
            questions_created = len(questions_data)
        
        # Commit final
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Base de datos inicializada correctamente',
            'users_created': users_created,
            'questions_created': questions_created,
            'credentials': [
                {
                    'role': user_data['role'],
                    'username': user_data['username'],
                    'password': user_data['password']
                }
                for user_data in users_to_create
            ] if existing_users == 0 else []
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Error inicializando base de datos: {str(e)}'
        }), 500

@app.route('/api/init-questions', methods=['POST'])
def init_questions():
    """Endpoint para inicializar las preguntas de evaluación en producción"""
    try:
        # Verificar si ya existe la evaluación
        existing_assessment = Assessment.query.filter_by(title='Evaluación de Asertividad').first()
        if existing_assessment:
            question_count = Question.query.filter_by(assessment_id=existing_assessment.id).count()
            return jsonify({
                'success': True,
                'message': f'Evaluación ya existe con {question_count} preguntas',
                'questions_created': 0
            })
        
        # Crear la evaluación principal
        assessment = Assessment(
            title='Evaluación de Asertividad',
            description='Evaluación para medir el nivel de asertividad en diferentes dimensiones',
            created_at=datetime.utcnow()
        )
        
        db.session.add(assessment)
        db.session.flush()  # Para obtener el ID
        
        # 10 preguntas básicas de asertividad
        questions_data = [
            'Cuando alguien me critica de manera injusta, expreso mi desacuerdo de forma clara y respetuosa.',
            'Me siento cómodo/a expresando mis opiniones en grupo, incluso si difieren de la mayoría.',
            'Puedo decir "no" cuando alguien me pide algo que no quiero o no puedo hacer.',
            'Cuando necesito ayuda, la pido sin sentirme incómodo/a.',
            'Defiendo mis derechos cuando siento que están siendo violados.',
            'Establezco límites claros en mis relaciones personales.',
            'Abordo los conflictos de frente en lugar de evitarlos.',
            'Mantengo la calma durante las discusiones difíciles.',
            'Confío en mis habilidades y capacidades.',
            'Me siento seguro/a de mis decisiones.'
        ]
        
        # Opciones de respuesta (escala Likert)
        response_options = [
            "Totalmente en desacuerdo",
            "En desacuerdo", 
            "Neutral",
            "De acuerdo",
            "Totalmente de acuerdo"
        ]
        
        # Crear las preguntas
        for content in questions_data:
            question = Question(
                assessment_id=assessment.id,
                content=content,
                question_type='likert',
                options=response_options
            )
            db.session.add(question)
        
        # Commit todos los cambios
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Preguntas de evaluación creadas correctamente',
            'questions_created': len(questions_data),
            'assessment_title': assessment.title
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Error creando preguntas: {str(e)}'
        }), 500

@app.route('/api/test-simple', methods=['POST', 'GET'])
def test_simple_endpoint():
    """Simple test endpoint to verify JSON serialization works"""
    try:
        # Just return a simple response without calling any other functions
        return jsonify({
            'status': 'success',
            'message': 'Simple endpoint working',
            'test_value': True,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error in simple endpoint: {str(e)}'
        }), 500

@app.route('/api/test-minimal-db', methods=['POST', 'GET'])
def test_minimal_db():
    """Test minimal database operations"""
    try:
        # Test just creating tables without any other operations
        db.create_all()
        
        return jsonify({
            'status': 'success',
            'message': 'Tables created successfully',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error creating tables: {str(e)}'
        }), 500

@app.route('/api/coach/assessment-details/<int:assessment_result_id>', methods=['GET'])
@coach_access_required
def get_assessment_details(assessment_result_id):
    """Obtener detalles completos de una evaluación específica incluyendo respuestas y análisis dimensional"""
    try:
        # Obtener el resultado de la evaluación
        assessment_result = AssessmentResult.query.get(assessment_result_id)
        if not assessment_result:
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.get(assessment_result.user_id)
        if not coachee or coachee.coach_id != current_user.id:
            return jsonify({'error': 'No tienes permiso para ver esta evaluación'}), 403
        
        # Obtener las respuestas individuales
        responses = Response.query.filter_by(assessment_result_id=assessment_result_id).all()
        
        # Obtener las preguntas para contexto
        questions = {}
        for response in responses:
            question = Question.query.get(response.question_id)
            if question:
                questions[response.question_id] = {
                    'content': question.content,
                    'options': question.options,
                    'question_type': question.question_type
                }
        
        # Calcular puntuaciones dimensionales desde las respuestas
        dimensional_scores = calculate_dimensional_scores_from_responses(responses)
        
        # Obtener datos demográficos si están disponibles
        demographic_data = None
        if hasattr(assessment_result, 'demographic_data') and assessment_result.demographic_data:
            demographic_data = json.loads(assessment_result.demographic_data)
        
        # Preparar respuesta detallada
        response_data = {
            'assessment_result': {
                'id': assessment_result.id,
                'score': assessment_result.score,
                'total_questions': assessment_result.total_questions,
                'completed_at': assessment_result.completed_at.isoformat() if assessment_result.completed_at else None,
                'result_text': assessment_result.result_text,
                'assertiveness_level': get_assertiveness_level(assessment_result.score) if assessment_result.score else 'No calculado'
            },
            'coachee': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'email': coachee.email
            },
            'demographic_data': demographic_data,
            'dimensional_scores': dimensional_scores,
            'responses': [
                {
                    'question_id': response.question_id,
                    'question_content': questions.get(response.question_id, {}).get('content', 'Pregunta no encontrada'),
                    'selected_option': response.selected_option,
                    'selected_text': questions.get(response.question_id, {}).get('options', [])[response.selected_option - 1] if response.selected_option and response.selected_option <= len(questions.get(response.question_id, {}).get('options', [])) else 'Opción no válida',
                    'question_type': questions.get(response.question_id, {}).get('question_type', 'unknown')
                }
                for response in responses
            ],
            'analysis': {
                'strengths': get_assessment_strengths(dimensional_scores),
                'areas_for_improvement': get_assessment_improvements(dimensional_scores),
                'recommendations': get_coach_recommendations(dimensional_scores, assessment_result.score)
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo detalles de evaluación: {str(e)}'}), 500

def calculate_dimensional_scores_from_responses(responses):
    """Calcular puntuaciones dimensionales a partir de las respuestas almacenadas"""
    # Mapeo de preguntas a dimensiones
    question_to_dimension = {
        1: 'comunicacion',      # Pregunta 1
        2: 'opiniones',         # Pregunta 2  
        3: 'derechos',          # Pregunta 3
        4: 'comunicacion',      # Pregunta 4
        5: 'derechos',          # Pregunta 5
        6: 'derechos',          # Pregunta 6
        7: 'conflictos',        # Pregunta 7
        8: 'conflictos',        # Pregunta 8
        9: 'autoconfianza',     # Pregunta 9
        10: 'autoconfianza'     # Pregunta 10
    }
    
    dimension_scores = {
        'comunicacion': [],
        'derechos': [],
        'opiniones': [],
        'conflictos': [],
        'autoconfianza': []
    }
    
    # Agrupar respuestas por dimensión
    for response in responses:
        dimension = question_to_dimension.get(response.question_id)
        if dimension and response.selected_option:
            # Convertir respuesta a puntuación (escala Likert 1-5)
            points = response.selected_option  # 1=Totalmente en desacuerdo, 5=Totalmente de acuerdo
            dimension_scores[dimension].append(points)
    
    # Calcular promedios y convertir a escala 0-100
    final_scores = {}
    for dimension, scores in dimension_scores.items():
        if scores:
            avg_score = sum(scores) / len(scores)
            final_scores[dimension] = round((avg_score / 5) * 100, 1)
        else:
            # Si no hay preguntas para esta dimensión, usar promedio general
            all_scores = [score for scores_list in dimension_scores.values() for score in scores_list if scores_list]
            if all_scores:
                general_avg = sum(all_scores) / len(all_scores)
                final_scores[dimension] = round((general_avg / 5) * 100, 1)
            else:
                final_scores[dimension] = 50.0  # Valor neutral por defecto
    
    return final_scores

def get_assessment_strengths(dimensional_scores):
    """Identificar fortalezas basadas en las puntuaciones dimensionales"""
    strengths = []
    
    for dimension, score in dimensional_scores.items():
        if score >= 70:
            dimension_names = {
                'comunicacion': 'Comunicación Asertiva',
                'derechos': 'Defensa de Derechos',
                'opiniones': 'Expresión de Opiniones',
                'conflictos': 'Manejo de Conflictos',
                'autoconfianza': 'Autoconfianza'
            }
            strengths.append({
                'dimension': dimension_names.get(dimension, dimension),
                'score': score,
                'description': get_strength_description(dimension, score)
            })
    
    return strengths

def get_assessment_improvements(dimensional_scores):
    """Identificar áreas de mejora basadas en las puntuaciones dimensionales"""
    improvements = []
    
    for dimension, score in dimensional_scores.items():
        if score < 60:
            dimension_names = {
                'comunicacion': 'Comunicación Asertiva',
                'derechos': 'Defensa de Derechos',
                'opiniones': 'Expresión de Opiniones',
                'conflictos': 'Manejo de Conflictos',
                'autoconfianza': 'Autoconfianza'
            }
            improvements.append({
                'dimension': dimension_names.get(dimension, dimension),
                'score': score,
                'description': get_improvement_description(dimension, score)
            })
    
    return improvements

def get_strength_description(dimension, score):
    """Obtener descripción de fortaleza por dimensión"""
    descriptions = {
        'comunicacion': f'Excelente habilidad para comunicarse de manera clara y directa (Puntuación: {score}%). Mantiene un estilo comunicativo equilibrado.',
        'derechos': f'Muy buena capacidad para defender sus derechos de manera apropiada (Puntuación: {score}%). Establece límites saludables.',
        'opiniones': f'Gran facilidad para expresar opiniones personales de forma respetuosa (Puntuación: {score}%). No teme diferir de otros.',
        'conflictos': f'Excelente manejo de situaciones conflictivas (Puntuación: {score}%). Aborda los problemas de manera constructiva.',
        'autoconfianza': f'Alta confianza en sus propias habilidades y decisiones (Puntuación: {score}%). Mantiene una autoimagen positiva.'
    }
    return descriptions.get(dimension, f'Fortaleza en {dimension} (Puntuación: {score}%)')

def get_improvement_description(dimension, score):
    """Obtener descripción de área de mejora por dimensión"""
    descriptions = {
        'comunicacion': f'Oportunidad de mejorar la comunicación directa y clara (Puntuación: {score}%). Considerar practicar expresión de necesidades.',
        'derechos': f'Área de desarrollo en la defensa de derechos personales (Puntuación: {score}%). Importante trabajar en establecer límites.',
        'opiniones': f'Espacio para crecer en la expresión de opiniones personales (Puntuación: {score}%). Practicar compartir puntos de vista únicos.',
        'conflictos': f'Oportunidad de mejorar el manejo de conflictos (Puntuación: {score}%). Desarrollar estrategias de resolución constructiva.',
        'autoconfianza': f'Área de desarrollo en confianza personal (Puntuación: {score}%). Trabajar en reconocimiento de fortalezas propias.'
    }
    return descriptions.get(dimension, f'Área de mejora en {dimension} (Puntuación: {score}%)')

def get_coach_recommendations(dimensional_scores, overall_score):
    """Generar recomendaciones específicas para el coach"""
    recommendations = []
    
    # Recomendaciones basadas en puntuación general
    if overall_score < 50:
        recommendations.append("Considerar un enfoque de desarrollo integral de habilidades asertivas")
        recommendations.append("Establecer metas pequeñas y alcanzables para construir confianza")
    elif overall_score < 70:
        recommendations.append("Enfocarse en las dimensiones con menor puntuación para un desarrollo equilibrado")
        recommendations.append("Practicar situaciones específicas relacionadas con las áreas de mejora")
    else:
        recommendations.append("Mantener y refinar las fortalezas identificadas")
        recommendations.append("Considerar rol de mentor para otros en desarrollo de asertividad")
    
    # Recomendaciones específicas por dimensión
    lowest_dimension = min(dimensional_scores.items(), key=lambda x: x[1])
    highest_dimension = max(dimensional_scores.items(), key=lambda x: x[1])
    
    dimension_recommendations = {
        'comunicacion': "Ejercicios de comunicación clara y directa",
        'derechos': "Práctica en establecimiento de límites personales",
        'opiniones': "Desarrollo de confianza para expresar puntos de vista únicos",
        'conflictos': "Entrenamiento en técnicas de resolución de conflictos",
        'autoconfianza': "Trabajo en reconocimiento y valoración de logros personales"
    }
    
    if lowest_dimension[1] < 60:
        recommendations.append(f"Priorizar trabajo en: {dimension_recommendations.get(lowest_dimension[0], lowest_dimension[0])}")
    
    if highest_dimension[1] > 80:
        recommendations.append(f"Aprovechar fortaleza en {highest_dimension[0]} como base para otras áreas")
    
    return recommendations

@app.route('/api/coach/coachee-evaluations/<int:coachee_id>', methods=['GET'])
@coach_access_required
def get_coachee_evaluations(coachee_id):
    """Obtener todas las evaluaciones de un coachee específico con resumen"""
    try:
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id).first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no asignado'}), 404
        
        # Obtener todas las evaluaciones del coachee
        assessments = AssessmentResult.query.filter_by(
            user_id=coachee_id
        ).order_by(AssessmentResult.completed_at.desc()).all()
        
        evaluations_data = []
        for assessment in assessments:
            # Obtener respuestas para esta evaluación
            responses = Response.query.filter_by(assessment_result_id=assessment.id).all()
            dimensional_scores = calculate_dimensional_scores_from_responses(responses)
            
            evaluation_summary = {
                'id': assessment.id,
                'completed_at': assessment.completed_at.isoformat() if assessment.completed_at else None,
                'score': assessment.score,
                'total_questions': assessment.total_questions,
                'assertiveness_level': get_assertiveness_level(assessment.score) if assessment.score else 'No calculado',
                'dimensional_scores': dimensional_scores,
                'result_summary': assessment.result_text
            }
            
            evaluations_data.append(evaluation_summary)
        
        return jsonify({
            'coachee': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'email': coachee.email
            },
            'evaluations': evaluations_data,
            'total_evaluations': len(evaluations_data),
            'latest_score': evaluations_data[0]['score'] if evaluations_data else None,
            'progress_trend': calculate_progress_trend([e['score'] for e in evaluations_data if e['score']])
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo evaluaciones: {str(e)}'}), 500

def calculate_progress_trend(scores):
    """Calcular tendencia de progreso basada en las puntuaciones"""
    if len(scores) < 2:
        return 'insufficient_data'
    
    # Calcular la pendiente de la regresión lineal simple
    x_values = list(range(len(scores)))
    y_values = scores
    
    n = len(x_values)
    sum_x = sum(x_values)
    sum_y = sum(y_values)
    sum_xy = sum(x * y for x, y in zip(x_values, y_values))
    sum_xx = sum(x * x for x in x_values)
    
    # Pendiente (m) y ordenada al origen (b) de la recta de regresión
    m = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x ** 2)
    b = (sum_y - m * sum_x) / n
    
    # Predecir valores y calcular la tendencia
    trend = ['neutral' for _ in scores]  # Valor por defecto
    for i in range(len(scores)):
        predicted_value = m * i + b
        if predicted_value < scores[i]:
            trend[i] = 'up'
        elif predicted_value > scores[i]:
            trend[i] = 'down'
    
    return trend

