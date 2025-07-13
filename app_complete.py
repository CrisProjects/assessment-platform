#!/usr/bin/env python3
"""
Aplicación Flask completa con frontend y backend integrados
Perfecta para desplegar en Render como un solo servicio
FIXED: Botón 'Iniciar Evaluación' - Endpoint /api/register actualizado
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import json
import secrets
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func
import sqlite3

# Funciones de análisis de coach (módulo no disponible)
# Definimos funciones dummy para evitar errores
COACH_ANALYSIS_AVAILABLE = False

def calculate_dimensional_scores_from_responses(*args, **kwargs):
    """Función dummy para análisis dimensional"""
    return {}

def get_assessment_strengths(*args, **kwargs):
    """Función dummy para fortalezas de evaluación"""
    return []

def get_assessment_improvements(*args, **kwargs):
    """Función dummy para mejoras de evaluación"""
    return []

def get_coach_recommendations(*args, **kwargs):
    """Función dummy para recomendaciones del coach"""
    return []

def calculate_progress_trend(*args, **kwargs):
    """Función dummy para tendencia de progreso"""
    return {}

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-fixed-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de sesiones permanentes (no expiran automáticamente)
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # 30 días de duración
app.config['SESSION_PERMANENT'] = True

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
login_manager.login_view = 'dashboard_selection'  # Redirigir a página de selección cuando se requiere login
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'info'

# Handler personalizado para peticiones de API no autenticadas
@login_manager.unauthorized_handler
def unauthorized():
    # Si es una petición a una API (comienza con /api/), devolver JSON
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.'}), 401
    # Para otras rutas, hacer redirect normal
    return redirect(url_for('dashboard_selection'))

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
    assessments = db.relationship('AssessmentResult', foreign_keys='AssessmentResult.user_id', backref='user', lazy=True)

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
    text = db.Column(db.Text, nullable=False)  # Cambiado de 'content' a 'text'
    question_type = db.Column(db.String(50), default='likert')  # Cambiado default
    order = db.Column(db.Integer)  # Agregado campo order

class AssessmentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    score = db.Column(db.Float)
    total_questions = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    result_text = db.Column(db.Text)
    
    # Campos adicionales para tracking del coach
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Coach que supervisó
    invitation_id = db.Column(db.Integer, db.ForeignKey('invitation.id'), nullable=True)  # Invitación origen
    participant_name = db.Column(db.String(200), nullable=True)  # Nombre del participante
    participant_email = db.Column(db.String(120), nullable=True)  # Email del participante
    dimensional_scores = db.Column(db.JSON, nullable=True)  # Puntuaciones por dimensión
    
    # Relaciones
    coach = db.relationship('User', foreign_keys=[coach_id], backref='supervised_assessments')
    invitation = db.relationship('Invitation', backref='assessment_results')

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_option = db.Column(db.Integer)
    assessment_result_id = db.Column(db.Integer, db.ForeignKey('assessment_result.id'), nullable=True)

class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False)
    
    # Relaciones
    coach = db.relationship('User', backref='sent_invitations')
    
    def is_valid(self):
        """Verificar si la invitación es válida"""
        return not self.is_used and datetime.utcnow() < self.expires_at
    
    def mark_as_used(self):
        """Marcar invitación como usada"""
        self.is_used = True
        self.used_at = datetime.utcnow()

@login_manager.user_loader
def load_user(user_id):
    # Usar Session.get() en lugar del método deprecado Query.get()
    return db.session.get(User, int(user_id))

# Función auxiliar para obtener usuario coachee (regular o temporal)
def get_current_coachee():
    """Obtiene el usuario coachee actual, ya sea por login regular o sesión temporal"""
    # Primero verificar si hay un usuario logueado regular
    if current_user.is_authenticated and current_user.role == 'coachee':
        print(f"DEBUG: Usuario coachee regular encontrado: {current_user.id}")
        return current_user
    
    # Si no, verificar si hay una sesión temporal de coachee
    temp_coachee_id = session.get('temp_coachee_id')
    print(f"DEBUG: temp_coachee_id en sesión: {temp_coachee_id}")
    if temp_coachee_id:
        user = db.session.get(User, temp_coachee_id)
        print(f"DEBUG: Usuario temporal encontrado: {user.id if user else 'None'}")
        return user
    
    print("DEBUG: No se encontró usuario coachee")
    return None

# Decorador personalizado para rutas de coachee que permite sesiones temporales
def coachee_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        coachee_user = get_current_coachee()
        if not coachee_user:
            return redirect(url_for('dashboard_selection'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador personalizado para APIs de coachee que permite sesiones temporales
def coachee_api_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        coachee_user = get_current_coachee()
        if not coachee_user:
            return jsonify({'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.'}), 401
        # Añadir el usuario coachee a kwargs para que la función pueda usarlo
        kwargs['current_coachee'] = coachee_user
        return f(*args, **kwargs)
    return decorated_function

# ====================================================
# INICIALIZACIÓN AUTOMÁTICA DE BASE DE DATOS EN PRODUCCIÓN
# ====================================================
def auto_initialize_database():
    """Inicialización automática completa para producción (Render, etc.)"""
    try:
        print("🚀 AUTO-INICIALIZACIÓN: Verificando base de datos...")
        
        # Crear todas las tablas
        db.create_all()
        print("✅ AUTO-INIT: db.create_all() ejecutado")
        
        # Verificar tabla crítica 'user'
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'user' not in tables:
            print("🔧 AUTO-INIT: Tabla 'user' no existe, creando...")
            User.__table__.create(db.engine, checkfirst=True)
            
            # Re-verificar
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
        if 'user' in tables:
            print("✅ AUTO-INIT: Tabla 'user' confirmada")
            
            # Crear usuario admin si no existe
            try:
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    print("👤 AUTO-INIT: Creando usuario admin...")
                    admin_user = User(
                        username='admin',
                        email='admin@assessment.com',
                        full_name='Platform Administrator',
                        role='platform_admin'
                    )
                    admin_user.set_password('admin123')
                    db.session.add(admin_user)
                    db.session.commit()
                    print("✅ AUTO-INIT: Usuario admin creado")
                else:
                    print("ℹ️ AUTO-INIT: Usuario admin ya existe")
            except Exception as user_err:
                print(f"⚠️ AUTO-INIT: Error creando usuario admin: {user_err}")
        else:
            print("❌ AUTO-INIT: Tabla 'user' NO pudo ser creada")
        
        # ===== INICIALIZACIÓN DEL ASSESSMENT DE ASERTIVIDAD =====
        try:
            # Verificar si existe el assessment principal
            assessment = Assessment.query.filter_by(id=1).first()
            if not assessment:
                print("📝 AUTO-INIT: Creando assessment de asertividad...")
                assessment = Assessment(
                    id=1,
                    title='Evaluación de Asertividad',
                    description='Evaluación completa de habilidades asertivas en diferentes situaciones'
                )
                db.session.add(assessment)
                db.session.commit()
                print("✅ AUTO-INIT: Assessment de asertividad creado")
            else:
                print("ℹ️ AUTO-INIT: Assessment de asertividad ya existe")
            
            # Verificar y crear las 10 preguntas de asertividad
            existing_questions = Question.query.filter_by(assessment_id=1).count()
            if existing_questions == 0:
                print("❓ AUTO-INIT: Creando 10 preguntas de asertividad...")
                
                assertiveness_questions = [
                    "Cuando alguien me crítica injustamente, expreso mi desacuerdo de manera calmada y directa.",
                    "Puedo decir 'no' a las peticiones de otros sin sentirme culpable.",
                    "Expreso mis opiniones abiertamente, incluso cuando difieren de las de otros.",
                    "Cuando estoy en desacuerdo con algo, lo digo de manera respetuosa.",
                    "Me resulta fácil pedir ayuda cuando la necesito.",
                    "Puedo dar retroalimentación constructiva sin herir los sentimientos de otros.",
                    "Defiendo mis derechos sin agredir a los demás.",
                    "Expreso mis emociones de manera apropiada y en el momento adecuado.",
                    "Puedo manejar conflictos de manera constructiva.",
                    "Me siento cómodo/a expresando mis necesidades y deseos."
                ]
                
                for i, question_text in enumerate(assertiveness_questions, 1):
                    question = Question(
                        assessment_id=1,
                        text=question_text,
                        question_type='likert',
                        order=i
                    )
                    db.session.add(question)
                
                db.session.commit()
                print(f"✅ AUTO-INIT: {len(assertiveness_questions)} preguntas de asertividad creadas")
            else:
                print(f"ℹ️ AUTO-INIT: Ya existen {existing_questions} preguntas de asertividad")
                
        except Exception as assessment_err:
            print(f"⚠️ AUTO-INIT: Error inicializando assessment: {assessment_err}")
            
        # ===== CREAR USUARIOS DE PRUEBA ADICIONALES =====
        try:
            # *** COACH MANAGEMENT DISABLED ***
            # Los coaches ya existen en la base de datos con datos reales
            # Credenciales: coach@assessment.com / coach123
            print("🛡️ AUTO-INIT: Gestión de coaches deshabilitada para preservar datos reales")
            
            # Solo verificar que existe al menos un coach
            coach_count = User.query.filter_by(role='coach').count()
            if coach_count > 0:
                print(f"✅ AUTO-INIT: {coach_count} coaches encontrados en la base de datos")
                # Asegurar que el coach principal tenga la contraseña correcta
                main_coach = User.query.filter_by(email='coach@assessment.com').first()
                if main_coach:
                    main_coach.set_password('coach123')
                    db.session.commit()
                    print(f"🔧 AUTO-INIT: Contraseña del coach '{main_coach.full_name}' lista para acceso")
            else:
                print("⚠️ AUTO-INIT: No se encontraron coaches en la base de datos")
                
            # Crear coachee de prueba si no existe
            coachee_user = User.query.filter_by(email='coachee@assessment.com').first()
            if not coachee_user:
                print("👤 AUTO-INIT: Creando usuario coachee de prueba...")
                coachee_user = User(
                    username='coachee',
                    email='coachee@assessment.com',
                    full_name='Coachee de Prueba',
                    role='coachee'
                )
                coachee_user.set_password('coachee123')
                db.session.add(coachee_user)
                print("✅ AUTO-INIT: Usuario coachee creado")
            else:
                print("ℹ️ AUTO-INIT: Usuario coachee ya existe")
                
            db.session.commit()
            
        except Exception as users_err:
            print(f"⚠️ AUTO-INIT: Error creando usuarios de prueba: {users_err}")
            
        print(f"📋 AUTO-INIT: Tablas disponibles: {tables}")
        print("🎉 AUTO-INIT: Inicialización completa finalizada")
        return True
        
    except Exception as e:
        print(f"❌ AUTO-INIT: Error en inicialización automática: {e}")
        return False

# Ejecutar inicialización automática cuando el módulo se importe
# (Esto es especialmente importante para Render y otros servicios de hosting)
try:
    with app.app_context():
        auto_initialize_database()
except Exception as auto_init_error:
    print(f"⚠️ Error en auto-inicialización: {auto_init_error}")

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
        target_user = db.session.get(User, target_user_id)
        return target_user and target_user.coach_id == current_user.id
    elif current_user.is_coachee:
        # Coachee solo puede acceder a sus propios datos
        return current_user.id == target_user_id
    return False

# Rutas del Frontend
@app.route('/')
def index():
    """Pantalla principal de selección de dashboards"""
    return render_template('dashboard_selection.html')

@app.route('/api/status')
def api_status():
    """API endpoint para verificar el estado del sistema"""
    return jsonify({
        'status': 'success',
        'message': 'Assessment Platform API is running',
        'version': '2.0.0',
        'available_endpoints': ['/coachee-dashboard', '/coach-dashboard', '/admin-dashboard']
    })

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ========================
# RUTAS DE AUTENTICACIÓN
# ========================

# Login Routes
@app.route('/login')
def login():
    """Servir la página de login"""
    return render_template('login.html')

# API Routes
@app.route('/dashboard_selection')
def dashboard_selection():
    """Servir la página de selección de dashboards"""
    return render_template('dashboard_selection.html')

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
            session.permanent = True  # Hacer la sesión permanente
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

@app.route('/logout')
def logout_page():
    """Logout y redirección a la página principal"""
    logout_user()
    # Limpiar sesiones temporales si existen
    session.pop('temp_coachee_id', None)
    session.pop('temp_coachee_token', None)
    session.clear()
    return redirect('/')

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    """Logout API"""
    logout_user()
    # Limpiar sesiones temporales si existen
    session.pop('temp_coachee_id', None)
    session.pop('temp_coachee_token', None)
    session.clear()
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
        
        # Crear nuevo usuario con rol especificado o coachee por defecto
        role = data.get('role', 'coachee')
        # Validar que el rol sea válido
        valid_roles = ['coachee', 'coach', 'platform_admin']
        if role not in valid_roles:
            role = 'coachee'
            
        new_user = User(
            username=data['username'],
            email=data['email'],
            full_name=data['full_name'],
            role=role
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
        return '/coachee-dashboard'  # Coachees van a su dashboard de evaluación

# ========================
# RUTAS DE ADMINISTRADOR
# ========================

@app.route('/admin-login')
def admin_login_page():
    """Página de login específica para administrador"""
    return render_template('admin_login.html')

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    """Login API específico para administrador"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        # Buscar específicamente el usuario admin
        admin_user = User.query.filter(
            User.username == username,
            User.role == 'platform_admin'
        ).first()
        
        if admin_user and admin_user.check_password(password) and admin_user.is_active:
            login_user(admin_user, remember=True)
            session.permanent = True  # Hacer la sesión permanente
            admin_user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'user': {
                    'id': admin_user.id,
                    'username': admin_user.username,
                    'full_name': admin_user.full_name,
                    'email': admin_user.email,
                    'role': admin_user.role
                },
                'redirect_url': '/platform-admin-dashboard'
            }), 200
        else:
            return jsonify({'error': 'Credenciales de administrador inválidas'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/admin/change-password', methods=['POST'])
def api_admin_change_password():
    """Cambiar contraseña del administrador"""
    try:
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Contraseña actual y nueva contraseña son requeridas'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'La nueva contraseña debe tener al menos 6 caracteres'}), 400
        
        # Buscar el usuario admin
        admin_user = User.query.filter_by(username='admin', role='platform_admin').first()
        
        if not admin_user:
            return jsonify({'error': 'Usuario administrador no encontrado'}), 404
        
        # Verificar contraseña actual
        if not admin_user.check_password(current_password):
            return jsonify({'error': 'Contraseña actual incorrecta'}), 401
        
        # Actualizar contraseña
        admin_user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error al cambiar contraseña: {str(e)}'}), 500

@app.route('/api/admin/create-coach', methods=['POST'])
def api_admin_create_coach():
    """Crear un nuevo usuario Coach - Solo para administradores"""
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['username', 'email', 'full_name', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        username = data.get('username')
        email = data.get('email')
        full_name = data.get('full_name')
        password = data.get('password')
        
        # Validar formato de email básico
        if '@' not in email:
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        # Validar longitud de contraseña
        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Verificar si el usuario ya existe
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'El nombre de usuario ya está en uso'}), 400
            else:
                return jsonify({'error': 'El email ya está registrado'}), 400
        
        # Crear nuevo coach
        new_coach = User(
            username=username,
            email=email,
            full_name=full_name,
            role='coach',
            is_active=True
        )
        new_coach.set_password(password)
        
        db.session.add(new_coach)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Coach {full_name} creado exitosamente',
            'coach': {
                'id': new_coach.id,
                'username': new_coach.username,
                'email': new_coach.email,
                'full_name': new_coach.full_name,
                'role': new_coach.role,
                'created_at': new_coach.created_at.isoformat() if new_coach.created_at else None
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creando coach: {str(e)}'}), 500

@app.route('/api/admin/coaches', methods=['GET'])
def api_admin_get_coaches():
    """Obtener lista de todos los coaches - Solo para administradores"""
    try:
        coaches = User.query.filter_by(role='coach').order_by(User.created_at.desc()).all()
        
        coaches_data = []
        for coach in coaches:
            # Contar coachees asignados
            coachees_count = User.query.filter_by(coach_id=coach.id, role='coachee').count()
            
            # Contar evaluaciones supervisadas
            assessments_count = AssessmentResult.query.filter_by(coach_id=coach.id).count()
            
            coaches_data.append({
                'id': coach.id,
                'username': coach.username,
                'email': coach.email,
                'full_name': coach.full_name,
                'is_active': coach.is_active,
                'created_at': coach.created_at.isoformat() if coach.created_at else None,
                'last_login': coach.last_login.isoformat() if coach.last_login else None,
                'coachees_count': coachees_count,
                'assessments_count': assessments_count
            })
        
        return jsonify({
            'success': True,
            'coaches': coaches_data,
            'total_coaches': len(coaches_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo coaches: {str(e)}'}), 500

# ========================
# RUTAS PARA COACHES
# ========================

@app.route('/coach-login')
def coach_login_page():
    """Página de login específica para coaches"""
    return render_template('coach_login.html')

@app.route('/api/coach/login', methods=['POST'])
def api_coach_login():
    """Login API específico para coaches"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        # Buscar usuario coach
        coach_user = User.query.filter(
            (User.username == username) | (User.email == username),
            User.role == 'coach'
        ).first()
        
        if coach_user and coach_user.check_password(password) and coach_user.is_active:
            login_user(coach_user, remember=True)
            session.permanent = True  # Hacer la sesión permanente
            coach_user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'user': {
                    'id': coach_user.id,
                    'username': coach_user.username,
                    'full_name': coach_user.full_name,
                    'email': coach_user.email,
                    'role': coach_user.role
                },
                'redirect_url': '/coach-dashboard'
            }), 200
        else:
            return jsonify({'error': 'Credenciales de coach inválidas o cuenta desactivada'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/coach/change-password', methods=['POST'])
@login_required
def api_coach_change_password():
    """Cambiar contraseña del coach autenticado"""
    try:
        # Verificar que el usuario es un coach
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado: Solo coaches pueden usar este endpoint'}), 403
        
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Contraseña actual y nueva contraseña son requeridas'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'La nueva contraseña debe tener al menos 6 caracteres'}), 400
        
        # Verificar contraseña actual
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Contraseña actual incorrecta'}), 401
        
        # Actualizar contraseña
        current_user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error al cambiar contraseña: {str(e)}'}), 500

@app.route('/api/coach/profile', methods=['GET'])
@login_required
def api_coach_get_profile():
    """Obtener perfil del coach autenticado"""
    try:
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Estadísticas del coach
        coachees_count = User.query.filter_by(coach_id=current_user.id, role='coachee').count()
        assessments_count = AssessmentResult.query.filter_by(coach_id=current_user.id).count()
        
        return jsonify({
            'success': True,
            'profile': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'full_name': current_user.full_name,
                'role': current_user.role,
                'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
                'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
                'coachees_count': coachees_count,
                'assessments_count': assessments_count
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

@app.route('/api/coach/create-invitation', methods=['POST'])
@login_required
def api_coach_create_invitation():
    """Crear una invitación para un nuevo coachee"""
    try:
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado: Solo coaches pueden crear invitaciones'}), 403
        
        data = request.get_json()
        full_name = data.get('full_name')
        email = data.get('email')
        
        if not full_name or not email:
            return jsonify({'error': 'Nombre completo y email son requeridos'}), 400
        
        # Validar formato de email básico
        if '@' not in email:
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        # Verificar si ya existe una invitación activa para este email
        existing_invitation = Invitation.query.filter_by(
            coach_id=current_user.id,
            email=email,
            is_used=False
        ).first()
        
        if existing_invitation and existing_invitation.is_valid():
            return jsonify({'error': 'Ya existe una invitación activa para este email'}), 400
        
        # Crear nueva invitación
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=30)  # Válida por 30 días
        
        new_invitation = Invitation(
            coach_id=current_user.id,
            email=email,
            full_name=full_name,
            token=token,
            expires_at=expires_at
        )
        
        db.session.add(new_invitation)
        db.session.commit()
        
        # Generar URL de invitación
        base_url = request.url_root.rstrip('/')
        invitation_url = f"{base_url}/evaluate/{token}"  # Cambiar a /evaluate/ directamente
        
        return jsonify({
            'success': True,
            'message': f'Invitación creada para {full_name}',
            'invitation': {
                'id': new_invitation.id,
                'email': email,
                'full_name': full_name,
                'token': token,
                'expires_at': expires_at.isoformat(),
                'invitation_url': invitation_url
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creando invitación: {str(e)}'}), 500

@app.route('/api/coach/my-coachees', methods=['GET'])
@login_required
def api_coach_get_coachees():
    """Obtener lista de coachees del coach autenticado"""
    try:
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado: Solo coaches pueden ver coachees'}), 403
        
        # Obtener coachees asignados
        coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').all()
        
        coachees_data = []
        for coachee in coachees:
            # Obtener última evaluación
            latest_assessment = AssessmentResult.query.filter_by(
                user_id=coachee.id
            ).order_by(AssessmentResult.completed_at.desc()).first()
            
            # Contar evaluaciones totales
            total_assessments = AssessmentResult.query.filter_by(user_id=coachee.id).count()
            
            coachee_data = {
                'id': coachee.id,
                'username': coachee.username,
                'email': coachee.email,
                'full_name': coachee.full_name,
                'created_at': coachee.created_at.isoformat() if coachee.created_at else None,
                'total_assessments': total_assessments,
                'latest_assessment': None
            }
            
            if latest_assessment:
                coachee_data['latest_assessment'] = {
                    'id': latest_assessment.id,
                    'score': latest_assessment.score,
                    'overall_score': latest_assessment.score,  # Para compatibilidad
                    'completed_at': latest_assessment.completed_at.isoformat(),
                    'created_at': latest_assessment.completed_at.isoformat(),  # Para compatibilidad
                    'dimensional_scores': latest_assessment.dimensional_scores or {}
                }
            
            coachees_data.append(coachee_data)
        
        return jsonify(coachees_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo coachees: {str(e)}'}), 500

@app.route('/api/coach/dashboard-stats', methods=['GET'])
@login_required
def api_coach_dashboard_stats():
    """Obtener estadísticas del dashboard del coach"""
    try:
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado: Solo coaches pueden ver estadísticas'}), 403
        
        # DEBUG: Log del usuario actual
        print(f"🔍 DEBUG - Current user: ID={current_user.id}, Name={current_user.full_name}, Email={current_user.email}")
        
        # Contar coachees
        total_coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').count()
        print(f"🔍 DEBUG - Total coachees found: {total_coachees}")
        
        # Contar evaluaciones totales supervisadas
        total_assessments = AssessmentResult.query.filter_by(coach_id=current_user.id).count()
        print(f"🔍 DEBUG - Total assessments found: {total_assessments}")
        
        # Calcular puntuación promedio
        avg_score_result = db.session.query(func.avg(AssessmentResult.score)).filter_by(
            coach_id=current_user.id
        ).scalar()
        avg_score = round(avg_score_result, 1) if avg_score_result else 0
        
        # Actividad reciente (evaluaciones del último mes)
        last_month = datetime.utcnow() - timedelta(days=30)
        recent_activity = AssessmentResult.query.filter(
            AssessmentResult.coach_id == current_user.id,
            AssessmentResult.completed_at >= last_month
        ).count()
        
        # Distribución de niveles de asertividad
        score_distribution = {
            'Poco Asertivo': 0,
            'Moderadamente Asertivo': 0,
            'Asertivo': 0,
            'Muy Asertivo': 0
        }
        
        assessments = AssessmentResult.query.filter_by(coach_id=current_user.id).all()
        for assessment in assessments:
            if assessment.score:
                if assessment.score < 40:
                    score_distribution['Poco Asertivo'] += 1
                elif assessment.score < 60:
                    score_distribution['Moderadamente Asertivo'] += 1
                elif assessment.score < 80:
                    score_distribution['Asertivo'] += 1
                else:
                    score_distribution['Muy Asertivo'] += 1
        
        # Datos de progreso por coachee (TODAS las evaluaciones - MISMA FUENTE que distribución)
        progress_data = []
        
        # Obtener todos los coachees del coach
        coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').all()
        
        for coachee in coachees:
            # Obtener TODAS las evaluaciones del coachee (sin filtro temporal - MISMA FUENTE que distribución)
            coachee_assessments = AssessmentResult.query.filter(
                AssessmentResult.user_id == coachee.id
            ).order_by(AssessmentResult.completed_at).all()
            
            if coachee_assessments:
                coachee_progress = {
                    'coachee_name': coachee.full_name,
                    'coachee_id': coachee.id,
                    'assessments': []
                }
                
                for assessment in coachee_assessments:
                    coachee_progress['assessments'].append({
                        'date': assessment.completed_at.isoformat(),
                        'score': assessment.score
                    })
                
                progress_data.append(coachee_progress)
        
        return jsonify({
            'coach_name': current_user.full_name,
            'total_coachees': total_coachees,
            'total_assessments': total_assessments,
            'avg_score': avg_score,
            'recent_activity': recent_activity,
            'score_distribution': score_distribution,
            'progress_data': progress_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo estadísticas: {str(e)}'}), 500

@app.route('/api/questions', methods=['GET'])
def api_questions():
    """API endpoint para obtener las preguntas del assessment"""
    try:
        # Usar query SQL directa para evitar problemas de metadatos SQLAlchemy
        conn = sqlite3.connect('assessments.db')
        cursor = conn.cursor()
        
        # Primero verificar que existe el assessment
        cursor.execute('SELECT COUNT(*) FROM assessment WHERE id = 1')
        if cursor.fetchone()[0] == 0:
            conn.close()
            return jsonify({'error': 'Assessment no encontrado'}), 404
        
        # Obtener las preguntas directamente de SQLite
        cursor.execute('''
            SELECT id, assessment_id, text, question_type, "order"
            FROM question 
            WHERE assessment_id = 1 
            ORDER BY "order"
        ''')
        
        questions_data = cursor.fetchall()
        conn.close()
        
        if not questions_data:
            return jsonify({'error': 'No se encontraron preguntas para este assessment'}), 404
        
        # Formatear las preguntas para el frontend
        formatted_questions = []
        
        # Opciones estándar para preguntas tipo Likert
        likert_options = [
            "Totalmente en desacuerdo",
            "En desacuerdo", 
            "Neutral",
            "De acuerdo",
            "Totalmente de acuerdo"
        ]
        
        for question_data in questions_data:
            # question_data es una tuple: (id, assessment_id, text, question_type, order)
            formatted_questions.append({
                'id': question_data[0],
                'content': question_data[2],  # text
                'options': likert_options,
                'question_type': question_data[3] if question_data[3] else 'likert'
            })
        
        return jsonify({
            'success': True,
            'assessment_id': 1,
            'assessment_title': 'Evaluación de Asertividad',
            'total_questions': len(formatted_questions),
            'questions': formatted_questions
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo preguntas: {str(e)}'}), 500

@app.route('/api/save_assessment', methods=['POST'])
@coachee_api_required
def api_save_assessment(current_coachee):
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
            
        # Validar que todas las respuestas estén en el rango correcto
        valid_answers = {}
        for q_idx, answer in answers.items():
            try:
                answer_value = int(answer)
                if 1 <= answer_value <= 5:
                    valid_answers[q_idx] = answer_value
            except (ValueError, TypeError):
                continue
        
        if len(valid_answers) == 0:
            return jsonify({'error': 'No se recibieron respuestas válidas'}), 400
        
        # Calcular dimensiones usando la misma lógica del frontend
        dimensional_scores = calculate_dimensional_scores_backend(valid_answers)
        
        # Calcular puntuación total
        total_score = sum(dimensional_scores.values()) / len(dimensional_scores)
        
        # Determinar nivel de asertividad
        assertiveness_level = get_assertiveness_level(total_score)
        
        # Obtener información adicional del coachee
        coach_id = current_coachee.coach_id if hasattr(current_coachee, 'coach_id') else None
        participant_name = current_coachee.full_name if hasattr(current_coachee, 'full_name') else None
        participant_email = current_coachee.email if hasattr(current_coachee, 'email') else None
        
        # Crear resultado de evaluación
        assessment_result = AssessmentResult(
            user_id=current_coachee.id,
            assessment_id=1,  # Asumiendo que tenemos una evaluación con ID 1
            score=total_score,
            total_questions=len(valid_answers),
            result_text=f"Nivel: {assertiveness_level}, Puntuaciones: {dimensional_scores}",
            coach_id=coach_id,
            participant_name=participant_name,
            participant_email=participant_email,
            dimensional_scores=dimensional_scores
        )
        
        db.session.add(assessment_result)
        db.session.flush()  # Flush to get the ID without committing
        
        # Guardar respuestas individuales para análisis detallado
        # Obtener los IDs reales de las preguntas desde la base de datos
        questions = Question.query.filter_by(assessment_id=1).order_by(Question.order).all()
        
        for question_index, answer in valid_answers.items():
            idx = int(question_index)
            if idx < len(questions):  # Verificar que el índice sea válido
                question_id = questions[idx].id
                # La validación ya se hizo arriba, answer ya es un entero válido
                response = Response(
                    user_id=current_coachee.id,
                    question_id=question_id,
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
        }), 200
        
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
        try:
            idx = int(question_index)
            answer_value = int(answer)
            
            # Validar que la respuesta esté en el rango correcto (1-5)
            if not (1 <= answer_value <= 5):
                continue  # Saltar respuestas inválidas
                
            if idx in question_to_dimension:
                dimension = question_to_dimension[idx]
                dimension_scores[dimension].append(answer_value)
        except (ValueError, TypeError):
            # Saltar respuestas que no se puedan convertir a entero
            continue
    
    # Calcular promedio por dimensión y convertir a porcentaje
    final_scores = {}
    for dimension, scores in dimension_scores.items():
        if scores:
            avg_score = sum(scores) / len(scores)
            # Convertir de escala 1-5 a 0-100
            percentage = ((avg_score - 1) / 4) * 100
            final_scores[dimension] = round(percentage, 1)
        else:
            final_scores[dimension] = 0
    
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

# ========================
# RUTAS DE DASHBOARD
# ========================

@app.route('/coach-dashboard')
@login_required
def coach_dashboard():
    """Dashboard específico para coaches"""
    if current_user.role != 'coach':
        flash('Acceso denegado. Solo coaches pueden acceder a esta página.', 'error')
        return redirect(url_for('login'))
    
    return render_template('coach_dashboard.html', user=current_user)

@app.route('/coachee-dashboard')
def coachee_dashboard():
    """Dashboard específico para coachees"""
    # Obtener el usuario coachee actual (regular o temporal)
    coachee_user = get_current_coachee()
    
    # Si no hay usuario y estamos en desarrollo, hacer auto-login con usuario de prueba
    if not coachee_user and not (os.environ.get('RENDER') or os.environ.get('VERCEL') or os.environ.get('PRODUCTION')):
        print("🔧 DESARROLLO: Auto-login con usuario coachee de prueba para Safari")
        test_coachee = User.query.filter_by(username='coachee', role='coachee').first()
        if test_coachee:
            login_user(test_coachee, remember=True)
            session.permanent = True
            coachee_user = test_coachee
            flash('Auto-login activado para desarrollo (Safari compatible)', 'info')
    
    # Si aún no hay usuario, redirigir a selección de dashboard
    if not coachee_user:
        flash('Por favor inicia sesión como coachee', 'warning')
        return redirect(url_for('dashboard_selection'))
    
    # Preparar datos del participante
    participant_data = {
        'name': coachee_user.full_name,
        'email': coachee_user.email,
        'coach_name': coachee_user.coach.full_name if coachee_user.coach else 'Sin asignar'
    }
    
    # Buscar el token de invitación (si existe)
    invitation_token = session.get('temp_coachee_token')  # Primero verificar sesión temporal
    if not invitation_token:
        # Si no hay token temporal, buscar en la base de datos
        invitation = Invitation.query.filter_by(
            email=coachee_user.email,
            is_used=True
        ).order_by(Invitation.used_at.desc()).first()
        
        if invitation:
            invitation_token = invitation.token
    
    return render_template('coachee_dashboard.html', 
                         user=coachee_user, 
                         participant_data=participant_data,
                         invitation_token=invitation_token)

@app.route('/platform-admin-dashboard')
@login_required
def platform_admin_dashboard():
    """Dashboard específico para administradores de plataforma"""
    if current_user.role != 'platform_admin':
        flash('Acceso denegado. Solo administradores pueden acceder a esta página.', 'error')
        return redirect(url_for('login'))
    
    return render_template('admin_dashboard.html', user=current_user)

# Ruta genérica de admin-dashboard que redirije a platform-admin-dashboard
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    """Redirección desde admin-dashboard a platform-admin-dashboard"""
    if current_user.role != 'platform_admin':
        flash('Acceso denegado. Solo administradores pueden acceder a esta página.', 'error')
        return redirect(url_for('login'))
    
    return redirect(url_for('platform_admin_dashboard'))

# ========================
# INICIALIZACIÓN DE LA APLICACIÓN
# ========================

@app.route('/register/<token>')
def register_with_invitation(token):
    """Página de registro usando token de invitación"""
    try:
        # Buscar invitación válida
        invitation = Invitation.query.filter_by(token=token).first()
        
        if not invitation:
            flash('Invitación no encontrada o inválida', 'error')
            return redirect('/')
        
        if not invitation.is_valid():
            flash('Esta invitación ha expirado o ya fue utilizada', 'error')
            return redirect('/')
        
        # Renderizar página de registro con datos de la invitación
        return render_template('register_invitation.html', invitation=invitation)
        
    except Exception as e:
        flash(f'Error procesando invitación: {str(e)}', 'error')
        return redirect('/')

@app.route('/api/register-invitation', methods=['POST'])
def api_register_with_invitation():
    """Registrar usuario a través de invitación"""
    try:
        data = request.get_json()
        token = data.get('token')
        password = data.get('password')
        
        if not token or not password:
            return jsonify({'error': 'Token y contraseña son requeridos'}), 400
        
        # Buscar invitación válida
        invitation = Invitation.query.filter_by(token=token).first()
        
        if not invitation or not invitation.is_valid():
            return jsonify({'error': 'Invitación inválida o expirada'}), 400
        
        # Verificar si ya existe un usuario con este email
        existing_user = User.query.filter_by(email=invitation.email).first()
        if existing_user:
            return jsonify({'error': 'Ya existe un usuario con este email'}), 400
        
        # Crear nuevo usuario coachee
        new_user = User(
            username=data.get('username', invitation.email.split('@')[0]),  # Username por defecto
            email=invitation.email,
            full_name=invitation.full_name,
            role='coachee',
            coach_id=invitation.coach_id
        )
        new_user.set_password(password)
        
        # Marcar invitación como usada
        invitation.mark_as_used()
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Usuario registrado exitosamente',
            'user_id': new_user.id,
            'redirect_url': '/coachee-dashboard'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error en registro: {str(e)}'}), 500

@app.route('/evaluate/<token>')
def evaluate_with_invitation(token):
    """Página directa de evaluación usando token de invitación"""
    try:
        print(f"DEBUG: Accediendo con token: {token}")
        
        # Buscar invitación válida
        invitation = Invitation.query.filter_by(token=token).first()
        
        if not invitation:
            print(f"DEBUG: Invitación no encontrada para token: {token}")
            flash('Invitación no encontrada o inválida', 'error')
            return redirect('/')
        
        print(f"DEBUG: Invitación encontrada: {invitation.email}, used: {invitation.is_used}, valid: {invitation.is_valid()}")
        
        # Verificar si ya existe un usuario registrado con este email
        existing_user = User.query.filter_by(email=invitation.email).first()
        
        # Si el usuario ya existe, usar sesión temporal en lugar de login_user
        if existing_user:
            print(f"DEBUG: Usuario existente encontrado: {existing_user.id}")
            # Usar sesión temporal para coachees que no interfiera con sesiones de coaches
            session['temp_coachee_id'] = existing_user.id
            session['temp_coachee_token'] = token
            session.permanent = True
            flash(f'Bienvenido de nuevo, {existing_user.full_name}!', 'success')
            return redirect('/coachee-dashboard')
        
        # Si no existe usuario, verificar que la invitación sea válida
        if not invitation.is_valid():
            print(f"DEBUG: Invitación inválida - used: {invitation.is_used}, expires_at: {invitation.expires_at}")
            flash('Esta invitación ha expirado o ya fue utilizada', 'error')
            return redirect('/')
        
        print(f"DEBUG: Creando nuevo usuario para: {invitation.email}")
        # Resto del código para crear nuevo usuario...
        # Si no existe el usuario, crearlo automáticamente con una contraseña temporal
        temp_password = secrets.token_urlsafe(12)  # Contraseña temporal de 16 caracteres
        username = invitation.email.split('@')[0]  # Username basado en el email
        
        # Verificar que el username sea único
        counter = 1
        original_username = username
        while User.query.filter_by(username=username).first():
            username = f"{original_username}{counter}"
            counter += 1
        
        # Crear nuevo usuario coachee
        new_user = User(
            username=username,
            email=invitation.email,
            full_name=invitation.full_name,
            role='coachee',
            coach_id=invitation.coach_id
        )
        new_user.set_password(temp_password)
        
        # Marcar invitación como usada
        invitation.mark_as_used()
        
        db.session.add(new_user)
        db.session.commit()
        
        # Usar sesión temporal en lugar de login_user para no interferir con coaches
        session['temp_coachee_id'] = new_user.id
        session['temp_coachee_token'] = token
        session.permanent = True
        
        print(f"DEBUG: Usuario creado y sesión temporal establecida: {new_user.id}")
        
        # Mostrar mensaje con las credenciales temporales
        flash(f'¡Bienvenido {new_user.full_name}! Tu cuenta ha sido creada. Usuario: {username}, Contraseña temporal: {temp_password}', 'info')
        
        return redirect('/coachee-dashboard')
        
    except Exception as e:
        print(f"DEBUG: Error en evaluate_with_invitation: {str(e)}")
        flash(f'Error procesando invitación: {str(e)}', 'error')
        return redirect('/')

# ========================
# CONFIGURACIÓN DE COOKIES ADAPTABLE
# ========================

@app.route('/coachee-login-direct')
def coachee_login_direct():
    """Login directo como coachee para pruebas en Safari"""
    try:
        # Buscar el usuario coachee de prueba
        coachee_user = User.query.filter_by(username='coachee').first()
        
        if not coachee_user:
            flash('Usuario coachee de prueba no encontrado', 'error')
            return redirect(url_for('dashboard_selection'))
        
        # Hacer login directo del usuario
        login_user(coachee_user, remember=True)
        session.permanent = True
        
        flash(f'Login directo exitoso como {coachee_user.full_name}', 'success')
        return redirect('/coachee-dashboard')
        
    except Exception as e:
        flash(f'Error en login directo: {str(e)}', 'error')
        return redirect(url_for('dashboard_selection'))



# Configuración de cookies adaptable a desarrollo y producción

# Solo aplicar configuraciones seguras en producción (HTTPS)
if os.environ.get('RENDER') or os.environ.get('VERCEL') or os.environ.get('PRODUCTION'):
    # Configuración para producción en Render/Vercel
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'  
    app.config['SESSION_COOKIE_SECURE'] = True     
    print("🔒 Configuración de cookies SEGURA para producción")
else:
    # Configuración para desarrollo local (compatible con Safari)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # Más compatible con Safari
    app.config['SESSION_COOKIE_SECURE'] = False     # HTTP local
    print("🔓 Configuración de cookies LOCAL para desarrollo")

@app.route('/api/user/my-profile', methods=['GET'])
def api_user_my_profile():
    """API para obtener el perfil del usuario actual (coachee, coach o admin)"""
    try:
        # Para coachees que pueden usar sesiones temporales
        if not current_user.is_authenticated:
            coachee_user = get_current_coachee()
            if coachee_user:
                return jsonify({
                    'success': True,
                    'user': {
                        'id': coachee_user.id,
                        'username': coachee_user.username,
                        'full_name': coachee_user.full_name,
                        'email': coachee_user.email,
                        'role': coachee_user.role,
                        'coach_id': coachee_user.coach_id,
                        'session_type': 'temporary_coachee'
                    }
                }), 200
            else:
                return jsonify({'error': 'Usuario no autenticado'}), 401
        
        # Para usuarios regulares autenticados
        return jsonify({
            'success': True,
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'full_name': current_user.full_name,
                'email': current_user.email,
                'role': current_user.role,
                'coach_id': getattr(current_user, 'coach_id', None),
                'session_type': 'authenticated'
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

@app.route('/coach/auto-login')
def coach_auto_login():
    """Auto-login para coach en desarrollo (Solo para testing)"""
    # Solo permitir en desarrollo
    if os.environ.get('RENDER') or os.environ.get('VERCEL') or os.environ.get('PRODUCTION'):
        flash('Auto-login solo disponible en desarrollo', 'warning')
        return redirect(url_for('coach_login_page'))
    
    try:
        # Buscar el coach principal
        coach_user = User.query.filter_by(email='coach@assessment.com', role='coach').first()
        if not coach_user:
            # Si no existe, buscar cualquier coach disponible
            coach_user = User.query.filter_by(role='coach').first()
        
        if coach_user:
            login_user(coach_user, remember=True)
            session.permanent = True
            coach_user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f'Auto-login exitoso como coach: {coach_user.full_name}', 'success')
            return redirect(url_for('coach_dashboard'))
        else:
            flash('No se encontraron usuarios coach para auto-login', 'error')
            return redirect(url_for('coach_login_page'))
            
    except Exception as e:
        flash(f'Error en auto-login: {str(e)}', 'error')
        return redirect(url_for('coach_login_page'))

if __name__ == '__main__':
    with app.app_context():
        auto_initialize_database()
    
    # Ejecutar la aplicación
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)