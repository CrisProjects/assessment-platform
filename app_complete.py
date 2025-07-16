#!/usr/bin/env python3
"""
Aplicación Flask completa con frontend y backend integrados
Perfecta para desplegar en Render como un solo servicio
FIXED: Botón 'Iniciar Evaluación' - Endpoint /api/register actualizado
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import json
import secrets
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-fixed-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Constantes de la aplicación
DEFAULT_ASSESSMENT_ID = 1
LIKERT_SCALE_MIN = 1
LIKERT_SCALE_MAX = 5

# Configuración de sesiones permanentes (no expiran automáticamente)
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # 30 días de duración
app.config['SESSION_PERMANENT'] = True

# Configuraciones mejoradas de cookies para múltiples sesiones
app.config['SESSION_COOKIE_SECURE'] = False  # True en producción HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Mayor seguridad
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Permite múltiples pestañas
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_SECURE'] = False  # True en producción HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

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
    
    # Redirigir al login específico según la ruta solicitada
    if request.path.startswith('/platform-admin') or request.path.startswith('/admin'):
        return redirect(url_for('admin_login_page'))
    elif request.path.startswith('/coach'):
        return redirect(url_for('coach_login_page'))
    else:
        # Para otras rutas, hacer redirect a selección de dashboard
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

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)  # 'comunicacion', 'derechos', 'opiniones', 'conflictos', 'autoconfianza'
    priority = db.Column(db.String(20), default='medium')  # 'low', 'medium', 'high', 'urgent'
    due_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relaciones
    coach = db.relationship('User', foreign_keys=[coach_id], backref='assigned_tasks')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_tasks')
    progress_entries = db.relationship('TaskProgress', backref='task', lazy=True, cascade='all, delete-orphan')

class TaskProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'in_progress', 'completed', 'cancelled'
    progress_percentage = db.Column(db.Integer, default=0)  # 0-100
    notes = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Coach o Coachee que actualizó
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    updated_by_user = db.relationship('User', backref='task_updates')

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

# Decorador para rutas que requieren acceso de administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Autenticación requerida'}), 401
        if current_user.role != 'platform_admin':
            return jsonify({'error': 'Acceso denegado. Solo administradores pueden acceder a esta función.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Decorador para rutas que requieren acceso de coach
def coach_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Autenticación requerida'}), 401
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden acceder a esta función.'}), 403
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
            existing_questions = Question.query.filter_by(assessment_id=DEFAULT_ASSESSMENT_ID).count()
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
                        assessment_id=DEFAULT_ASSESSMENT_ID,
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
# Evitamos doble inicialización usando una bandera global
_db_initialized = False

def ensure_database_initialized():
    """Asegurar que la base de datos esté inicializada una sola vez"""
    global _db_initialized
    if not _db_initialized:
        try:
            with app.app_context():
                auto_initialize_database()
                _db_initialized = True
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
@app.route('/dashboard-selection')  # Ruta alternativa con guión
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
        }, 201)
        
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
@admin_required
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
        
        # Verificar contraseña actual (current_user ya está autenticado como admin)
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

@app.route('/api/admin/create-coach', methods=['POST'])
@admin_required
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
@admin_required
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

@app.route('/api/admin/platform-stats', methods=['GET'])
@admin_required
def api_admin_platform_stats():
    """Obtener estadísticas generales de la plataforma - Solo para administradores"""
    try:
        # Contar usuarios por rol
        total_users = User.query.count()
        total_coaches = User.query.filter_by(role='coach').count()
        total_coachees = User.query.filter_by(role='coachee').count()
        total_admins = User.query.filter_by(role='platform_admin').count()
        
        # Contar evaluaciones totales
        total_assessments = AssessmentResult.query.count()
        
        # Calcular puntuación promedio global
        avg_score_result = db.session.query(func.avg(AssessmentResult.score)).scalar()
        avg_score = round(avg_score_result, 1) if avg_score_result else 0
        
        # Evaluaciones del último mes
        last_month = datetime.utcnow() - timedelta(days=30)
        recent_assessments = AssessmentResult.query.filter(
            AssessmentResult.completed_at >= last_month
        ).count()
        
        # Distribución de usuarios activos vs inactivos
        active_users = User.query.filter_by(is_active=True).count()
        inactive_users = User.query.filter_by(is_active=False).count()
        
        # Datos para gráfico de distribución de usuarios
        user_distribution = {
            'coaches': total_coaches,
            'coachees': total_coachees,
            'admins': total_admins
        }
        
        return jsonify({
            'success': True,
            'total_users': total_users,
            'total_coaches': total_coaches,
            'total_coachees': total_coachees,
            'total_admins': total_admins,
            'total_assessments': total_assessments,
            'avg_score': avg_score,
            'recent_assessments': recent_assessments,
            'active_users': active_users,
            'inactive_users': inactive_users,
            'user_distribution': user_distribution
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo estadísticas: {str(e)}'}), 500

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

@app.route('/api/coach/create-coachee-with-credentials', methods=['POST'])
@login_required
def api_coach_create_coachee_with_credentials():
    """Crear un coachee directamente con credenciales de acceso"""
    try:
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado: Solo coaches pueden crear coachees'}), 403
        
        data = request.get_json()
        full_name = data.get('full_name')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        
        # Validaciones
        if not all([full_name, email, username, password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'El usuario debe tener al menos 3 caracteres'}), 400
            
        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Validar formato de email
        if '@' not in email:
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        # Validar formato de usuario
        import re
        if not re.match(r'^[a-zA-Z0-9._]+$', username):
            return jsonify({'error': 'El usuario solo puede contener letras, números, puntos y guiones bajos'}), 400
        
        # Verificar si el username ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'El nombre de usuario ya está en uso'}), 400
        
        # Verificar si el email ya existe
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return jsonify({'error': 'El email ya está registrado'}), 400
        
        # Crear nuevo coachee
        new_coachee = User(
            username=username,
            email=email,
            full_name=full_name,
            role='coachee',
            coach_id=current_user.id,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        # Establecer contraseña
        new_coachee.set_password(password)
        
        db.session.add(new_coachee)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Coachee {full_name} creado exitosamente',
            'coachee': {
                'id': new_coachee.id,
                'username': new_coachee.username,
                'email': new_coachee.email,
                'full_name': new_coachee.full_name,
                'created_at': new_coachee.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creando coachee: {str(e)}'}), 500

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
        cursor.execute(f'SELECT COUNT(*) FROM assessment WHERE id = {DEFAULT_ASSESSMENT_ID}')
        if cursor.fetchone()[0] == 0:
            conn.close()
            return jsonify({'error': 'Assessment no encontrado'}), 404
        
        # Obtener las preguntas directamente de SQLite
        cursor.execute(f'''
            SELECT id, assessment_id, text, question_type, "order"
            FROM question 
            WHERE assessment_id = {DEFAULT_ASSESSMENT_ID} 
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
        
        # Validar y procesar respuestas
        valid_answers = validate_assessment_answers(data.get('answers', {}))
        if not valid_answers:
            return jsonify({'error': 'No se recibieron respuestas válidas'}), 400
        
        # Calcular puntuaciones y crear resultado
        assessment_result = create_assessment_result(current_coachee, valid_answers, data)
        
        # Guardar respuestas individuales
        save_individual_responses(current_coachee, valid_answers, assessment_result.id)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'result_id': assessment_result.id,
            'total_score': int(assessment_result.score),
            'assertiveness_level': get_assertiveness_level(assessment_result.score),
            'dimensional_scores': assessment_result.dimensional_scores,
            'message': 'Evaluación guardada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error guardando evaluación: {str(e)}'}), 500

def generate_elegant_result_text(assertiveness_level, dimensional_scores):
    """Generar un texto de resultado elegante y amigable para el usuario"""
    
    # Mapeo de nombres de dimensiones a texto más amigable
    dimension_names = {
        'comunicacion': 'Comunicación',
        'derechos': 'Defensa de Derechos',
        'opiniones': 'Expresión de Opiniones',
        'conflictos': 'Manejo de Conflictos',
        'autoconfianza': 'Autoconfianza'
    }
    
    # Encontrar fortalezas (puntuaciones más altas)
    sorted_dimensions = sorted(dimensional_scores.items(), key=lambda x: x[1], reverse=True)
    top_strengths = [dimension_names.get(dim, dim) for dim, score in sorted_dimensions[:2] if score >= 70]
    
    # Crear texto base
    result_parts = [f"Nivel de Asertividad: {assertiveness_level}"]
    
    # Agregar fortalezas si las hay
    if top_strengths:
        if len(top_strengths) == 1:
            result_parts.append(f"Fortaleza principal: {top_strengths[0]}")
        else:
            result_parts.append(f"Fortalezas principales: {', '.join(top_strengths)}")
    
    # Agregar puntuación general
    avg_score = sum(dimensional_scores.values()) / len(dimensional_scores)
    result_parts.append(f"Puntuación general: {avg_score:.0f}%")
    
    return " • ".join(result_parts)

def validate_assessment_answers(answers):
    """Validar y procesar respuestas del assessment"""
    if not answers:
        return {}
        
    valid_answers = {}
    for q_idx, answer in answers.items():
        try:
            answer_value = int(answer)
            if LIKERT_SCALE_MIN <= answer_value <= LIKERT_SCALE_MAX:
                valid_answers[q_idx] = answer_value
        except (ValueError, TypeError):
            continue
    
    return valid_answers

def create_assessment_result(current_coachee, valid_answers, data):
    """Crear y guardar el resultado de la evaluación"""
    # Calcular dimensiones usando la misma lógica del frontend
    dimensional_scores = calculate_dimensional_scores_backend(valid_answers)
    
    # Calcular puntuación total
    total_score = sum(dimensional_scores.values()) / len(dimensional_scores)
    
    # Determinar nivel de asertividad
    assertiveness_level = get_assertiveness_level(total_score)
    
    # Obtener información adicional del coachee
    coach_id = getattr(current_coachee, 'coach_id', None)
    participant_name = getattr(current_coachee, 'full_name', None)
    participant_email = getattr(current_coachee, 'email', None)
    
    # Crear resultado de evaluación
    assessment_result = AssessmentResult(
        user_id=current_coachee.id,
        assessment_id=DEFAULT_ASSESSMENT_ID,  # Usando el assessment de asertividad principal
        score=total_score,
        total_questions=len(valid_answers),
        result_text=generate_elegant_result_text(assertiveness_level, dimensional_scores),
        coach_id=coach_id,
        participant_name=participant_name,
        participant_email=participant_email,
        dimensional_scores=dimensional_scores
    )
    
    db.session.add(assessment_result)
    db.session.flush()  # Flush to get the ID without committing
    
    return assessment_result

def save_individual_responses(current_coachee, valid_answers, assessment_result_id):
    """Guardar respuestas individuales para análisis detallado"""
    # Obtener los IDs reales de las preguntas desde la base de datos
    questions = Question.query.filter_by(assessment_id=DEFAULT_ASSESSMENT_ID).order_by(Question.order).all()
    
    for question_index, answer in valid_answers.items():
        idx = int(question_index)
        if idx < len(questions):  # Verificar que el índice sea válido
            question_id = questions[idx].id
            response = Response(
                user_id=current_coachee.id,
                question_id=question_id,
                selected_option=answer,
                assessment_result_id=assessment_result_id
            )
            db.session.add(response)

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
            if not (LIKERT_SCALE_MIN <= answer_value <= LIKERT_SCALE_MAX):
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
# RUTAS PARA COACHEES
# ========================

@app.route('/coachee-login')
def coachee_login_page():
    """Página de login específica para coachees"""
    return render_template('coachee_login.html')

@app.route('/coachee-login', methods=['POST'])
def coachee_login_form():
    """Manejo de login de coachee via formulario"""
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Usuario y contraseña requeridos', 'error')
            return redirect('/coachee-login')
        
        # Buscar usuario coachee
        coachee_user = User.query.filter(
            (User.username == username) | (User.email == username),
            User.role == 'coachee'
        ).first()
        
        if coachee_user and coachee_user.check_password(password) and coachee_user.is_active:
            login_user(coachee_user, remember=True)
            session.permanent = True
            coachee_user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash(f'Bienvenido, {coachee_user.full_name}', 'success')
            return redirect('/coachee-dashboard')
        else:
            flash('Credenciales de coachee inválidas o cuenta desactivada', 'error')
            return redirect('/coachee-login')
            
    except Exception as e:
        flash(f'Error en login: {str(e)}', 'error')
        return redirect('/coachee-login')

@app.route('/api/coachee/login', methods=['POST'])
def api_coachee_login():
    """Login API específico para coachees"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        # Buscar usuario coachee
        coachee_user = User.query.filter(
            (User.username == username) | (User.email == username),
            User.role == 'coachee'
        ).first()
        
        if coachee_user and coachee_user.check_password(password) and coachee_user.is_active:
            login_user(coachee_user, remember=True)
            session.permanent = True
            coachee_user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'user': {
                    'id': coachee_user.id,
                    'username': coachee_user.username,
                    'full_name': coachee_user.full_name,
                    'email': coachee_user.email,
                    'role': coachee_user.role
                },
                'redirect_url': '/coachee-dashboard'
            }), 200
        else:
            return jsonify({'error': 'Credenciales de coachee inválidas o cuenta desactivada'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/user/my-profile', methods=['GET'])
@coachee_api_required
def api_user_my_profile(current_coachee):
    """API para obtener el perfil del usuario coachee actual"""
    try:
        return jsonify({
            'success': True,
            'user': {
                'id': current_coachee.id,
                'username': current_coachee.username,
                'email': current_coachee.email,
                'full_name': current_coachee.full_name,
                'role': current_coachee.role,
                'created_at': current_coachee.created_at.strftime('%Y-%m-%d %H:%M') if current_coachee.created_at else None,
                'coach_id': current_coachee.coach_id
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

# ========================
# RUTAS DE DASHBOARD
# ========================

@app.route('/coach-dashboard')
@login_required
def coach_dashboard():
    """Dashboard específico para coaches"""
    if current_user.role != 'coach':
        flash('Acceso denegado. Solo coaches pueden acceder a esta página.', 'error')
        return redirect(url_for('coach_login_page'))
    
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
        return redirect(url_for('admin_login_page'))
    
    return render_template('admin_dashboard.html', user=current_user)

# Ruta genérica de admin-dashboard que redirije a platform-admin-dashboard
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    """Redirección desde admin-dashboard a platform-admin-dashboard"""
    if current_user.role != 'platform_admin':
        flash('Acceso denegado. Solo administradores pueden acceder a esta página.', 'error')
        return redirect(url_for('admin_login_page'))
    
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



# === API ROUTES FOR TASK MANAGEMENT ===

@app.route('/api/coach/evaluation-summary/<int:coachee_id>', methods=['GET'])
@coach_required
def api_coach_evaluation_summary(coachee_id):
    """API para obtener resumen de evaluaciones de un coachee específico"""
    try:
        # Verificar que el coachee pertenece a este coach
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id, role='coachee').first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no pertenece a este coach'}), 404
        
        # Obtener todas las evaluaciones del coachee
        assessments = AssessmentResult.query.filter_by(user_id=coachee_id).order_by(AssessmentResult.completed_at.desc()).all()
        
        if not assessments:
            return jsonify({
                'success': True,
                'coachee': {
                    'id': coachee.id,
                    'full_name': coachee.full_name,
                    'email': coachee.email
                },
                'summary': {
                    'total_assessments': 0,
                    'latest_assessment': None,
                    'average_scores': {},
                    'progress_trend': 'sin_datos',
                    'strengths': [],
                    'improvement_areas': [],
                    'recommendations': []
                }
            }), 200
        
        # Calcular estadísticas
        latest_assessment = assessments[0]
        total_assessments = len(assessments)
        
        # Intentar usar dimensional_scores si está disponible, sino calcular manualmente
        average_scores = {}
        
        if latest_assessment.dimensional_scores:
            try:
                dimensional_data = json.loads(latest_assessment.dimensional_scores) if isinstance(latest_assessment.dimensional_scores, str) else latest_assessment.dimensional_scores
                if dimensional_data and isinstance(dimensional_data, dict):
                    average_scores = dimensional_data
            except:
                pass
        
        # Si no hay dimensional_scores, calcular desde responses
        if not average_scores:
            # Obtener responses de la evaluación más reciente
            from sqlalchemy import text
            responses_query = text("""
                SELECT r.question_id, r.answer_value, q.dimension 
                FROM response r 
                JOIN question q ON r.question_id = q.id 
                WHERE r.assessment_result_id = :assessment_id
            """)
            
            try:
                with db.engine.connect() as conn:
                    responses_result = conn.execute(responses_query, assessment_id=latest_assessment.id)
                    responses = responses_result.fetchall()
                
                # Calcular promedios por dimensión
                dimension_totals = {
                    'comunicacion': 0, 'derechos': 0, 'opiniones': 0, 
                    'conflictos': 0, 'autoconfianza': 0
                }
                dimension_counts = {dim: 0 for dim in dimension_totals.keys()}
                
                for response in responses:
                    dimension = response[2]  # q.dimension
                    score = response[1]      # r.answer_value
                    if dimension in dimension_totals:
                        dimension_totals[dimension] += score
                        dimension_counts[dimension] += 1
                
                # Calcular promedios
                for dimension in dimension_totals:
                    if dimension_counts[dimension] > 0:
                        average_scores[dimension] = round(dimension_totals[dimension] / dimension_counts[dimension], 2)
                    else:
                        average_scores[dimension] = 0
            except Exception as e:
                print(f"Error calculando scores: {e}")
                # Valores por defecto
                average_scores = {
                    'comunicacion': 0, 'derechos': 0, 'opiniones': 0, 
                    'conflictos': 0, 'autoconfianza': 0
                }
        
        # Determinar tendencia de progreso
        progress_trend = 'estable'
        if len(assessments) >= 2:
            recent_avg = sum(average_scores.values()) / len(average_scores) if average_scores else 0
            older_score = assessments[1].score or 0
            
            if recent_avg > older_score + 5:
                progress_trend = 'mejorando'
            elif recent_avg < older_score - 5:
                progress_trend = 'empeorando'
        
        # Identificar fortalezas y áreas de mejora
        sorted_scores = sorted(average_scores.items(), key=lambda x: x[1], reverse=True)
        strengths = [dim for dim, score in sorted_scores[:2] if score >= 70]  # Convertido a porcentaje
        improvement_areas = [dim for dim, score in sorted_scores[-2:] if score < 60]  # Convertido a porcentaje
        
        # Generar recomendaciones básicas
        recommendations = []
        if 'comunicacion' in improvement_areas:
            recommendations.append("Practicar técnicas de comunicación asertiva y escucha activa")
        if 'derechos' in improvement_areas:
            recommendations.append("Reforzar conocimiento sobre derechos personales y límites")
        if 'opiniones' in improvement_areas:
            recommendations.append("Ejercitar la expresión de opiniones de forma clara y respetuosa")
        if 'conflictos' in improvement_areas:
            recommendations.append("Desarrollar estrategias de resolución de conflictos")
        if 'autoconfianza' in improvement_areas:
            recommendations.append("Trabajar en el fortalecimiento de la autoestima y confianza personal")
        
        return jsonify({
            'success': True,
            'coachee': {
                'id': coachee.id,
                'full_name': coachee.full_name,
                'email': coachee.email
            },
            'summary': {
                'total_assessments': total_assessments,
                'latest_assessment': {
                    'id': latest_assessment.id,
                    'date': latest_assessment.completed_at.strftime('%Y-%m-%d %H:%M'),
                    'score': latest_assessment.score or 0
                },
                'average_scores': average_scores,
                'progress_trend': progress_trend,
                'strengths': strengths,
                'improvement_areas': improvement_areas,
                'recommendations': recommendations
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo resumen de evaluaciones: {str(e)}'}), 500

@app.route('/api/coach/tasks', methods=['GET'])
@coach_required
def api_coach_get_tasks():
    """API para obtener todas las tareas del coach"""
    try:
        # Obtener tareas asignadas por este coach
        tasks = Task.query.filter_by(coach_id=current_user.id, is_active=True).order_by(Task.created_at.desc()).all()
        
        tasks_data = []
        for task in tasks:
            # Obtener último progreso
            latest_progress = TaskProgress.query.filter_by(task_id=task.id).order_by(TaskProgress.created_at.desc()).first()
            
            tasks_data.append({
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'category': task.category,
                'priority': task.priority,
                'due_date': task.due_date.strftime('%Y-%m-%d') if task.due_date else None,
                'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
                'coachee': {
                    'id': task.coachee.id,
                    'full_name': task.coachee.full_name,
                    'email': task.coachee.email
                },
                'current_status': latest_progress.status if latest_progress else 'pending',
                'current_progress': latest_progress.progress_percentage if latest_progress else 0,
                'last_update': latest_progress.created_at.strftime('%Y-%m-%d %H:%M') if latest_progress else None
            })
        
        return jsonify({
            'success': True,
            'tasks': tasks_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo tareas: {str(e)}'}), 500

@app.route('/api/coach/tasks', methods=['POST'])
@coach_required
def api_coach_create_task():
    """API para crear una nueva tarea para un coachee"""
    try:
        data = request.get_json()
        
        # Validar campos requeridos
        required_fields = ['coachee_id', 'title', 'description', 'category']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Verificar que el coachee pertenece a este coach
        coachee = User.query.filter_by(id=data['coachee_id'], coach_id=current_user.id, role='coachee').first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no pertenece a este coach'}), 404
        
        # Validar categoría
        valid_categories = ['comunicacion', 'derechos', 'opiniones', 'conflictos', 'autoconfianza']
        if data['category'] not in valid_categories:
            return jsonify({'error': 'Categoría inválida'}), 400
        
        # Validar prioridad
        valid_priorities = ['low', 'medium', 'high', 'urgent']
        priority = data.get('priority', 'medium')
        if priority not in valid_priorities:
            priority = 'medium'
        
        # Procesar fecha de vencimiento
        due_date = None
        if data.get('due_date'):
            try:
                due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Formato de fecha inválido. Use YYYY-MM-DD'}), 400
        
        # Crear la tarea
        new_task = Task(
            coach_id=current_user.id,
            coachee_id=data['coachee_id'],
            title=data['title'].strip(),
            description=data['description'].strip(),
            category=data['category'],
            priority=priority,
            due_date=due_date
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        # Crear entrada inicial de progreso
        initial_progress = TaskProgress(
            task_id=new_task.id,
            status='pending',
            progress_percentage=0,
            notes='Tarea creada por el coach',
            updated_by=current_user.id
        )
        
        db.session.add(initial_progress)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Tarea creada exitosamente',
            'task': {
                'id': new_task.id,
                'title': new_task.title,
                'description': new_task.description,
                'category': new_task.category,
                'priority': new_task.priority,
                'due_date': new_task.due_date.strftime('%Y-%m-%d') if new_task.due_date else None,
                'coachee': {
                    'id': coachee.id,
                    'full_name': coachee.full_name,
                    'email': coachee.email
                }
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creando tarea: {str(e)}'}), 500

@app.route('/api/coach/tasks/<int:task_id>/progress', methods=['PUT'])
@coach_required
def api_coach_update_task_progress(task_id):
    """API para actualizar el progreso de una tarea"""
    try:
        # Verificar que la tarea pertenece a este coach
        task = Task.query.filter_by(id=task_id, coach_id=current_user.id, is_active=True).first()
        if not task:
            return jsonify({'error': 'Tarea no encontrada o no pertenece a este coach'}), 404
        
        data = request.get_json()
        
        # Validar status
        valid_statuses = ['pending', 'in_progress', 'completed', 'cancelled']
        status = data.get('status', 'pending')
        if status not in valid_statuses:
            return jsonify({'error': 'Status inválido'}), 400
        
        # Validar progreso
        progress = data.get('progress_percentage', 0)
        if not isinstance(progress, int) or progress < 0 or progress > 100:
            return jsonify({'error': 'Progreso debe ser un entero entre 0 y 100'}), 400
        
        # Crear nueva entrada de progreso
        new_progress = TaskProgress(
            task_id=task_id,
            status=status,
            progress_percentage=progress,
            notes=data.get('notes', '').strip(),
            updated_by=current_user.id
        )
        
        db.session.add(new_progress)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Progreso de tarea actualizado exitosamente',
            'progress': {
                'id': new_progress.id,
                'status': new_progress.status,
                'progress_percentage': new_progress.progress_percentage,
                'notes': new_progress.notes,
                'updated_at': new_progress.created_at.strftime('%Y-%m-%d %H:%M')
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error actualizando progreso: {str(e)}'}), 500

@app.route('/api/coach/coachee-evaluation-details/<int:coachee_id>', methods=['GET'])
@coach_required
def api_coach_coachee_evaluation_details(coachee_id):
    """API para que el coach vea los detalles completos de la evaluación más reciente de un coachee"""
    try:
        # Verificar que el coachee esté asignado a este coach
        coachee = User.query.filter_by(
            id=coachee_id, 
            role='coachee', 
            coach_id=current_user.id
        ).first()
        
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no asignado a tu supervisión'}), 404
        
        # Buscar la evaluación más reciente del coachee
        latest_assessment = AssessmentResult.query.filter_by(
            user_id=coachee_id
        ).order_by(AssessmentResult.completed_at.desc()).first()
        
        if not latest_assessment:
            return jsonify({'error': 'El coachee no tiene evaluaciones completadas'}), 404
        
        # Procesar detalles de la evaluación usando la misma función que el coachee
        evaluation_details = process_evaluation_details(latest_assessment, coachee)
        
        # Agregar información del coachee para el coach
        evaluation_details['coachee_name'] = coachee.full_name
        evaluation_details['coachee_email'] = coachee.email
        
        return jsonify({
            'success': True,
            'evaluation': evaluation_details
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo detalles de evaluación del coachee: {str(e)}'}), 500

@app.route('/api/coachee/tasks', methods=['GET'])
@coachee_required
def api_coachee_get_tasks():
    """API para que los coachees vean sus tareas asignadas"""
    try:
        coachee_user = get_current_coachee()
        
        # Obtener tareas asignadas a este coachee
        tasks = Task.query.filter_by(coachee_id=coachee_user.id, is_active=True).order_by(Task.created_at.desc()).all()
        
        tasks_data = []
        for task in tasks:
            # Obtener último progreso
            latest_progress = TaskProgress.query.filter_by(task_id=task.id).order_by(TaskProgress.created_at.desc()).first()
            
            tasks_data.append({
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'category': task.category,
                'priority': task.priority,
                'due_date': task.due_date.strftime('%Y-%m-%d') if task.due_date else None,
                'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
                'coach': {
                    'id': task.coach.id,
                    'full_name': task.coach.full_name,
                    'email': task.coach.email
                },
                'current_status': latest_progress.status if latest_progress else 'pending',
                'current_progress': latest_progress.progress_percentage if latest_progress else 0,
                'last_update': latest_progress.created_at.strftime('%Y-%m-%d %H:%M') if latest_progress else None
            })
        
        return jsonify({
            'success': True,
            'tasks': tasks_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo tareas: {str(e)}'}), 500

@app.route('/api/coachee/tasks/<int:task_id>/progress', methods=['PUT'])
@coachee_required
def api_coachee_update_task_progress(task_id):
    """API para que los coachees actualicen el progreso de sus tareas"""
    try:
        coachee_user = get_current_coachee()
        
        # Verificar que la tarea pertenece a este coachee
        task = Task.query.filter_by(id=task_id, coachee_id=coachee_user.id, is_active=True).first()
        if not task:
            return jsonify({'error': 'Tarea no encontrada o no pertenece a este coachee'}), 404
        
        data = request.get_json()
        
        # Validar status (coachees no pueden cancelar tareas)
        valid_statuses = ['pending', 'in_progress', 'completed']
        status = data.get('status', 'pending')
        if status not in valid_statuses:
            return jsonify({'error': 'Status inválido'}), 400
        
        # Validar progreso
        progress = data.get('progress_percentage', 0)
        if not isinstance(progress, int) or progress < 0 or progress > 100:
            return jsonify({'error': 'Progreso debe ser un entero entre 0 y 100'}), 400
        
        # Crear nueva entrada de progreso
        new_progress = TaskProgress(
            task_id=task_id,
            status=status,
            progress_percentage=progress,
            notes=data.get('notes', '').strip(),
            updated_by=coachee_user.id
        )
        
        db.session.add(new_progress)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Progreso de tarea actualizado exitosamente',
            'progress': {
                'id': new_progress.id,
                'status': new_progress.status,
                'progress_percentage': new_progress.progress_percentage,
                'notes': new_progress.notes,
                'updated_at': new_progress.created_at.strftime('%Y-%m-%d %H:%M')
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error actualizando progreso: {str(e)}'}), 500

@app.route('/api/coachee/evaluations', methods=['GET'])
@coachee_required
def api_coachee_get_evaluations():
    """API para que los coachees vean sus evaluaciones disponibles y completadas"""
    try:
        coachee_user = get_current_coachee()
        
        # Evaluaciones completadas por este coachee
        completed_evaluations = AssessmentResult.query.filter_by(user_id=coachee_user.id).order_by(AssessmentResult.completed_at.desc()).all()
        
        evaluations_data = {
            'completed': [],
            'available': {
                'assertiveness': {
                    'id': 'assertiveness',
                    'title': 'Evaluación de Asertividad',
                    'description': 'Evalúa tu nivel de asertividad en diferentes situaciones',
                    'duration': '10-15 minutos',
                    'questions_count': 25,
                    'available': True
                }
            }
        }
        
        # Procesar evaluaciones completadas
        for assessment in completed_evaluations:
            eval_data = {
                'id': assessment.id,
                'type': 'assertiveness',
                'title': 'Evaluación de Asertividad',
                'total_score': assessment.score,
                'assertiveness_level': get_assertiveness_level(assessment.score),
                'result_description': getattr(assessment, 'result_text', 'N/A'),
                'completed_at': assessment.completed_at.strftime('%Y-%m-%d %H:%M'),
                'dimensional_scores': assessment.dimensional_scores or {}
            }
            evaluations_data['completed'].append(eval_data)
        
        return jsonify({
            'success': True,
            'evaluations': evaluations_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo evaluaciones: {str(e)}'}), 500

@app.route('/api/coachee/dashboard-summary', methods=['GET'])
@coachee_required
def api_coachee_dashboard_summary():
    """API para obtener un resumen completo del dashboard del coachee"""
    try:
        coachee_user = get_current_coachee()
        
        # Obtener última evaluación
        latest_assessment = AssessmentResult.query.filter_by(user_id=coachee_user.id).order_by(AssessmentResult.completed_at.desc()).first()
        
        # Obtener tareas pendientes
        pending_tasks = Task.query.filter_by(coachee_id=coachee_user.id, is_active=True).all()
        pending_count = 0
        overdue_count = 0
        
        for task in pending_tasks:
            latest_progress = TaskProgress.query.filter_by(task_id=task.id).order_by(TaskProgress.created_at.desc()).first()
            current_status = latest_progress.status if latest_progress else 'pending'
            
            if current_status != 'completed':
                pending_count += 1
                if task.due_date and task.due_date < datetime.utcnow().date():
                    overdue_count += 1
        
        # Obtener información del coach
        coach_info = None
        if coachee_user.coach_id:
            coach = User.query.filter_by(id=coachee_user.coach_id, role='coach').first()
            if coach:
                coach_info = {
                    'id': coach.id,
                    'name': coach.full_name,
                    'email': coach.email
                }
        
        summary = {
            'coachee': {
                'id': coachee_user.id,
                'name': coachee_user.full_name,
                'email': coachee_user.email,
                'joined_at': coachee_user.created_at.strftime('%Y-%m-%d') if coachee_user.created_at else None
            },
            'coach': coach_info,
            'latest_evaluation': None,
            'tasks_summary': {
                'total_active': len(pending_tasks),
                'pending': pending_count,
                'overdue': overdue_count
            },
            'evaluation_summary': {
                'total_completed': AssessmentResult.query.filter_by(user_id=coachee_user.id).count(),
                'available_types': ['assertiveness']
            }
        }
        
        if latest_assessment:
            summary['latest_evaluation'] = {
                'id': latest_assessment.id,
                'total_score': latest_assessment.score,
                'assertiveness_level': get_assertiveness_level(latest_assessment.score),
                'result_description': getattr(latest_assessment, 'result_text', 'N/A'),
                'completed_at': latest_assessment.completed_at.strftime('%Y-%m-%d'),
                'days_ago': (datetime.utcnow().date() - latest_assessment.completed_at.date()).days
            }
        
        return jsonify({
            'success': True,
            'summary': summary
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo resumen: {str(e)}'}), 500

@app.route('/api/coachee/evaluation-details/<int:evaluation_id>', methods=['GET'])
@coachee_required
def api_coachee_evaluation_details(evaluation_id):
    """API para obtener detalles completos de una evaluación específica"""
    try:
        coachee_user = get_current_coachee()
        
        # Buscar la evaluación específica del coachee
        assessment = AssessmentResult.query.filter_by(
            id=evaluation_id, 
            user_id=coachee_user.id
        ).first()
        
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        # Procesar detalles de la evaluación
        evaluation_details = process_evaluation_details(assessment, coachee_user)
        
        return jsonify({
            'success': True,
            'evaluation': evaluation_details
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo detalles de evaluación: {str(e)}'}), 500

def process_evaluation_details(assessment, coachee_user):
    """Procesar y generar detalles completos de una evaluación"""
    # Obtener respuestas y preguntas
    responses = Response.query.filter_by(
        user_id=coachee_user.id,
        assessment_result_id=assessment.id
    ).all()
    
    questions = Question.query.filter_by(assessment_id=assessment.assessment_id).order_by(Question.order).all()
    
    # Procesar respuestas para análisis detallado
    response_details, question_responses = process_response_details(responses, questions)
    
    # Recalcular puntuaciones dimensionales
    dimensional_scores = calculate_dimensional_scores_backend(question_responses)
    total_score = sum(dimensional_scores.values()) / len(dimensional_scores) if dimensional_scores else 0
    assertiveness_level = get_assertiveness_level(total_score)
    
    # Generar análisis completo
    dimension_analysis = generate_dimension_analysis(dimensional_scores)
    analysis_data = generate_assessment_analysis(assertiveness_level, dimensional_scores)
    
    return {
        'id': assessment.id,
        'title': 'Evaluación de Asertividad',
        'completed_at': assessment.completed_at.strftime('%Y-%m-%d %H:%M'),
        'total_score': round(total_score, 1),
        'total_percentage': round(total_score, 1),  # total_score ya es un porcentaje (0-100)
        'assertiveness_level': assertiveness_level,
        'dimensional_scores': dimensional_scores,
        'dimension_analysis': dimension_analysis,
        'response_details': sorted(response_details, key=lambda x: x['order']),
        'analysis': analysis_data,
        'radar_data': {
            'labels': [format_dimension_name(dim) for dim in dimensional_scores.keys()],
            'scores': list(dimensional_scores.values()),
            'percentages': list(dimensional_scores.values())  # dimensional_scores ya son porcentajes
        }
    }

def process_response_details(responses, questions):
    """Procesar detalles de respuestas individuales"""
    response_details = []
    question_responses = {}
    
    for response in responses:
        question = next((q for q in questions if q.id == response.question_id), None)
        if question:
            response_details.append({
                'question_id': question.id,
                'question_text': question.text,
                'response_value': response.selected_option,
                'order': question.order
            })
            question_responses[question.order - 1] = response.selected_option
    
    return response_details, question_responses

def generate_dimension_analysis(dimensional_scores):
    """Generar análisis por dimensión"""
    dimension_analysis = {}
    for dimension, score in dimensional_scores.items():
        dimension_analysis[dimension] = {
            'score': round(score, 1),
            'percentage': round(score, 1),  # score ya es un porcentaje (0-100)
            'level': get_dimension_level(score),
            'interpretation': get_dimension_interpretation(dimension, score),
            'recommendations': get_dimension_recommendations(dimension, score)
        }
    return dimension_analysis

def generate_assessment_analysis(assertiveness_level, dimensional_scores):
    """Generar análisis completo del assessment"""
    return {
        'strengths': get_assessment_strengths_detailed(dimensional_scores),
        'improvements': get_assessment_improvements_detailed(dimensional_scores),
        'general_recommendations': get_general_recommendations(assertiveness_level, dimensional_scores)
    }

def get_dimension_level(score):
    """Determinar el nivel de una dimensión específica basado en porcentaje (0-100)"""
    if score >= 90:
        return 'Excelente'
    elif score >= 80:
        return 'Muy Bueno'
    elif score >= 70:
        return 'Bueno'
    elif score >= 60:
        return 'Regular'
    elif score >= 50:
        return 'Mejorable'
    else:
        return 'Necesita Atención'

def get_dimension_interpretation(dimension, score):
    """Generar interpretación específica por dimensión"""
    interpretations = {
        'comunicacion': {
            'high': 'Tienes excelentes habilidades de comunicación asertiva. Sabes expresar tus ideas de manera clara y directa.',
            'medium': 'Tu comunicación es generalmente efectiva, pero puedes mejorar en la claridad y directness.',
            'low': 'Te beneficiarías de desarrollar habilidades de comunicación más directa y clara.'
        },
        'derechos': {
            'high': 'Tienes una excelente comprensión y defensa de tus derechos personales.',
            'medium': 'Generalmente reconoces tus derechos, pero a veces puedes dudar en defenderlos.',
            'low': 'Es importante que trabajes en reconocer y defender tus derechos personales.'
        },
        'conflictos': {
            'high': 'Manejas los conflictos de manera asertiva y constructiva.',
            'medium': 'Tu manejo de conflictos es adecuado, pero puedes mejorar en algunas situaciones.',
            'low': 'Te beneficiarías de desarrollar mejores estrategias para manejar conflictos.'
        },
        'autoconfianza': {
            'high': 'Tienes una excelente autoconfianza y seguridad en ti mismo.',
            'medium': 'Tu autoconfianza es buena, pero puede fluctuar en ciertas situaciones.',
            'low': 'Trabajar en tu autoconfianza te ayudará a ser más asertivo.'
        },
        'opiniones': {
            'high': 'Expresas tus opiniones de manera clara y respetuosa.',
            'medium': 'Generalmente compartes tus opiniones, pero a veces puedes ser indeciso.',
            'low': 'Te beneficiarías de practicar expresar tus opiniones de manera más directa.'
        }
    }
    
    level = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
    return interpretations.get(dimension, {}).get(level, 'Puntuación en desarrollo.')

def get_dimension_recommendations(dimension, score):
    """Generar recomendaciones específicas por dimensión"""
    recommendations = {
        'comunicacion': {
            'high': ['Mantén tu estilo de comunicación directa', 'Ayuda a otros a desarrollar estas habilidades'],
            'medium': ['Practica expresar tus ideas de manera más directa', 'Utiliza el contacto visual al comunicarte'],
            'low': ['Practica técnicas de comunicación asertiva', 'Toma un curso de habilidades comunicativas']
        },
        'derechos': {
            'high': ['Mantén tu capacidad de defender tus derechos', 'Ayuda a otros a reconocer los suyos'],
            'medium': ['Identifica situaciones donde no defiendes tus derechos', 'Practica decir "no" cuando es necesario'],
            'low': ['Aprende sobre tus derechos fundamentales', 'Practica defenderte en situaciones de bajo riesgo']
        },
        'conflictos': {
            'high': ['Mantén tu enfoque constructivo', 'Considera mediar en conflictos de otros'],
            'medium': ['Practica técnicas de resolución de conflictos', 'Mantén la calma en situaciones tensas'],
            'low': ['Aprende estrategias básicas de manejo de conflictos', 'Practica la comunicación no violenta']
        },
        'autoconfianza': {
            'high': ['Mantén tu autoestima positiva', 'Comparte tu seguridad con otros'],
            'medium': ['Identifica qué situaciones afectan tu confianza', 'Practica autoaceptación'],
            'low': ['Trabaja en reconocer tus fortalezas', 'Considera terapia de autoestima si es necesario']
        },
        'opiniones': {
            'high': ['Mantén tu capacidad de expresarte', 'Ayuda a otros a encontrar su voz'],
            'medium': ['Practica expresar opiniones en grupos pequeños', 'Prepara tus ideas antes de reuniones importantes'],
            'low': ['Comienza expresando opiniones en entornos seguros', 'Practica con amigos o familiares cercanos']
        }
    }
    
    level = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
    return recommendations.get(dimension, {}).get(level, ['Continúa desarrollando esta área.'])

def get_assessment_strengths_detailed(dimensional_scores):
    """Identificar fortalezas principales basadas en puntuaciones dimensionales"""
    strengths = []
    sorted_dimensions = sorted(dimensional_scores.items(), key=lambda x: x[1], reverse=True)
    
    for dimension, score in sorted_dimensions[:2]:  # Top 2 fortalezas
        if score >= 70:  # Convertido a porcentaje (70% equivale a 3.5 en escala 1-5)
            dimension_name = format_dimension_name(dimension)
            strengths.append({
                'dimension': dimension_name,
                'score': round(score, 1),
                'description': get_dimension_interpretation(dimension, score)
            })
    
    return strengths

def get_assessment_improvements_detailed(dimensional_scores):
    """Identificar áreas de mejora basadas en puntuaciones dimensionales"""
    improvements = []
    sorted_dimensions = sorted(dimensional_scores.items(), key=lambda x: x[1])
    
    for dimension, score in sorted_dimensions[:2]:  # Bottom 2 áreas de mejora
        if score < 80:  # Convertido a porcentaje (80% equivale a 4.0 en escala 1-5)
            dimension_name = format_dimension_name(dimension)
            improvements.append({
                'dimension': dimension_name,
                'score': round(score, 1),
                'description': get_dimension_interpretation(dimension, score),
                'recommendations': get_dimension_recommendations(dimension, score)
            })
    
    return improvements

def get_general_recommendations(assertiveness_level, dimensional_scores):
    """Generar recomendaciones generales basadas en el nivel de asertividad"""
    avg_score = sum(dimensional_scores.values()) / len(dimensional_scores)
    
    recommendations = []
    
    if avg_score >= 90:  # Convertido a porcentaje (4.5 -> 90%)
        recommendations = [
            "¡Excelente! Tu nivel de asertividad es muy alto. Mantén estas habilidades.",
            "Considera ser mentor de otros que estén desarrollando su asertividad.",
            "Continúa practicando para mantener tu nivel en diferentes contextos."
        ]
    elif avg_score >= 80:  # Convertido a porcentaje (4.0 -> 80%)
        recommendations = [
            "Tu asertividad está en un nivel muy bueno. Sigue practicando.",
            "Identifica situaciones específicas donde puedes ser aún más asertivo.",
            "Mantén la constancia en tu desarrollo personal."
        ]
    elif avg_score >= 70:  # Convertido a porcentaje (3.5 -> 70%)
        recommendations = [
            "Tu asertividad está en desarrollo. Hay áreas donde puedes mejorar.",
            "Practica técnicas de comunicación asertiva regularmente.",
            "Considera tomar un curso o workshop sobre asertividad."
        ]
    elif avg_score >= 60:  # Convertido a porcentaje (3.0 -> 60%)
        recommendations = [
            "Tienes una base sólida, pero hay espacio significativo para mejorar.",
            "Enfócate en las dimensiones con puntuaciones más bajas.",
            "Practica en situaciones de bajo riesgo antes de situaciones importantes."
        ]
    else:
        recommendations = [
            "Es importante que te enfoques en desarrollar tu asertividad.",
            "Considera buscar apoyo profesional para desarrollar estas habilidades.",
            "Comienza con ejercicios básicos de autoafirmación."
        ]
    
    return recommendations

def format_dimension_name(dimension):
    """Formatear nombres de dimensiones para mostrar"""
    dimension_names = {
        'comunicacion': 'Comunicación',
        'derechos': 'Defensa de Derechos',
        'conflictos': 'Manejo de Conflictos',
        'autoconfianza': 'Autoconfianza',
        'opiniones': 'Expresión de Opiniones'
    }
    return dimension_names.get(dimension, dimension.title())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=10000, debug=True)