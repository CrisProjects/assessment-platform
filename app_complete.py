#!/usr/bin/env python3
"""
Aplicación Flask completa con frontend y backend integrados
Perfecta para desplegar en Render como un solo servicio
FIXED: Botón 'Iniciar Evaluación' - Endpoint /api/register actualizado
"""
# Cargar variables de entorno desde .env
from dotenv import load_dotenv
load_dotenv()

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
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func

# Configurar logging
import logging
from logging.handlers import RotatingFileHandler

# Configuración de logging basada en entorno
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper())

# Configurar logging básico
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Configurar archivo de log si se especifica
log_file = os.environ.get('LOG_FILE')
if log_file and not IS_PRODUCTION:  # En desarrollo, usar archivo si se especifica
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10485760,  # 10MB
        backupCount=3
    )
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)
    logger.info(f"Logging configurado con archivo: {log_file}")

logger.info(f"Logging iniciado - Nivel: {logging.getLevelName(LOG_LEVEL)}, Producción: {IS_PRODUCTION}")

# Configuración de Flask
app = Flask(__name__)

# Configuración de SECRET_KEY más segura
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # En desarrollo, generar una clave aleatoria
    if os.environ.get('FLASK_ENV') == 'development' or os.environ.get('RAILWAY_ENVIRONMENT') == 'development':
        import secrets
        SECRET_KEY = secrets.token_hex(32)
        logger.warning("⚠️ DEVELOPMENT: Usando SECRET_KEY generada aleatoriamente")
    else:
        # En producción, requerir SECRET_KEY
        logger.error("❌ SECRET_KEY environment variable is required in production")
        # Para Railway, usar una clave por defecto en caso de emergencia
        if os.environ.get('RAILWAY_ENVIRONMENT'):
            SECRET_KEY = 'railway-emergency-key-assessment-platform-2025'
            logger.warning("⚠️ RAILWAY: Usando SECRET_KEY de emergencia")
        else:
            raise ValueError("SECRET_KEY environment variable is required in production")

app.config['SECRET_KEY'] = SECRET_KEY

# Configuración de base de datos mejorada para Railway
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///assessments.db')
# Railway PostgreSQL URLs sometimes start with postgres:// but SQLAlchemy needs postgresql://
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Constantes de la aplicación
DEFAULT_ASSESSMENT_ID = 1
LIKERT_SCALE_MIN = 1
LIKERT_SCALE_MAX = 5

# Configuración de sesiones permanentes (no expiran automáticamente)
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # 30 días de duración
app.config['SESSION_PERMANENT'] = True

# Configuraciones mejoradas de cookies con seguridad condicional
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION  # True en producción HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Mayor seguridad
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Permite múltiples pestañas
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_SECURE'] = IS_PRODUCTION  # True en producción HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# Configurar CORS con orígenes desde variables de entorno o lista predeterminada
allowed_origins = []

# Agregar orígenes desde variable de entorno si existe
env_origins = os.environ.get('ALLOWED_ORIGINS', '')
if env_origins:
    allowed_origins.extend([origin.strip() for origin in env_origins.split(',')])

# Agregar orígenes predeterminados para desarrollo y producción
default_origins = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://assessment-platform-1nuo.onrender.com',  # Render backend
    'https://assessment-platform-final.vercel.app',   # Vercel principal
    'https://assessment-platform-deploy.vercel.app'   # Vercel deploy
]

# En desarrollo, agregar localhost
if not IS_PRODUCTION:
    default_origins.extend([
        'http://localhost:5002',
        'http://127.0.0.1:5002'
    ])

# Combinar y eliminar duplicados
allowed_origins.extend(default_origins)
allowed_origins = list(set(allowed_origins))

CORS(app, 
     origins=allowed_origins, 
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
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    
    # Sistema de roles de 3 niveles
    role = db.Column(db.String(20), default='coachee', index=True)  # 'platform_admin', 'coach', 'coachee'
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Relación coach-coachee
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime, index=True)
    
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
    __tablename__ = 'assessment'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relaciones
    questions = db.relationship('Question', backref='assessment', lazy=True, cascade='all, delete-orphan')
    results = db.relationship('AssessmentResult', backref='assessment_ref', lazy=True)

class Question(db.Model):
    __tablename__ = 'question'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), default='likert')
    order = db.Column(db.Integer, index=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relaciones
    responses = db.relationship('Response', backref='question', lazy=True)

class AssessmentResult(db.Model):
    __tablename__ = 'assessment_result'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    score = db.Column(db.Float)
    total_questions = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    result_text = db.Column(db.Text)
    
    # Campos adicionales para tracking del coach
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    invitation_id = db.Column(db.Integer, db.ForeignKey('invitation.id'), nullable=True, index=True)
    participant_name = db.Column(db.String(200), nullable=True)
    participant_email = db.Column(db.String(120), nullable=True)
    dimensional_scores = db.Column(db.JSON, nullable=True)
    
    # Relaciones
    coach = db.relationship('User', foreign_keys=[coach_id], backref='supervised_assessments')
    invitation = db.relationship('Invitation', backref='assessment_results')
    
    # Índice compuesto para consultas frecuentes
    __table_args__ = (
        db.Index('idx_user_assessment', 'user_id', 'assessment_id'),
        db.Index('idx_coach_completed', 'coach_id', 'completed_at'),
    )

class Response(db.Model):
    __tablename__ = 'response'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False, index=True)
    selected_option = db.Column(db.Integer)
    assessment_result_id = db.Column(db.Integer, db.ForeignKey('assessment_result.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Índice compuesto para evitar respuestas duplicadas
    __table_args__ = (
        db.Index('idx_user_question', 'user_id', 'question_id'),
    )

class Invitation(db.Model):
    __tablename__ = 'invitation'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    full_name = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False, index=True)
    
    # Relaciones
    coach = db.relationship('User', foreign_keys=[coach_id], backref='sent_invitations')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_invitation')
    
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
        logger.debug(f"Usuario coachee regular encontrado: {current_user.id}")
        return current_user
    
    # Si no, verificar si hay una sesión temporal de coachee
    temp_coachee_id = session.get('temp_coachee_id')
    logger.debug(f"temp_coachee_id en sesión: {temp_coachee_id}")
    if temp_coachee_id:
        user = db.session.get(User, temp_coachee_id)
        logger.debug(f"Usuario temporal encontrado: {user.id if user else 'None'}")
        return user
    
    logger.debug("No se encontró usuario coachee")
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

# Decorador para logging de funciones críticas
def log_function_call(func_name=None):
    """Decorador para loggear llamadas a funciones críticas"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            name = func_name or f.__name__
            try:
                logger.debug(f"Calling {name}")
                result = f(*args, **kwargs)
                logger.debug(f"Completed {name} successfully")
                return result
            except Exception as e:
                logger.error(f"Error in {name}: {str(e)}")
                raise
        return decorated_function
    return decorator

# ====================================================
# INICIALIZACIÓN AUTOMÁTICA DE BASE DE DATOS EN PRODUCCIÓN
# ====================================================
def auto_initialize_database():
    """Inicialización automática completa para producción (Render, etc.)"""
    try:
        logger.info("🚀 AUTO-INICIALIZACIÓN: Verificando base de datos...")
        
        # Crear todas las tablas
        db.create_all()
        logger.info("✅ AUTO-INIT: db.create_all() ejecutado")
        
        # Verificar tabla crítica 'user'
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'user' not in tables:
            logger.warning("🔧 AUTO-INIT: Tabla 'user' no existe, creando...")
            User.__table__.create(db.engine, checkfirst=True)
            
            # Re-verificar
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
        if 'user' in tables:
            logger.info("✅ AUTO-INIT: Tabla 'user' confirmada")
            
            # Crear usuario admin si no existe
            try:
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    logger.info("👤 AUTO-INIT: Creando usuario admin...")
                    admin_user = User(
                        username='admin',
                        email='admin@assessment.com',
                        full_name='Platform Administrator',
                        role='platform_admin'
                    )
                    admin_user.set_password('admin123')
                    db.session.add(admin_user)
                    db.session.commit()
                    logger.info("✅ AUTO-INIT: Usuario admin creado")
                else:
                    logger.info("ℹ️ AUTO-INIT: Usuario admin ya existe")
            except Exception as user_err:
                logger.error(f"⚠️ AUTO-INIT: Error creando usuario admin: {user_err}")
        else:
            logger.error("❌ AUTO-INIT: Tabla 'user' NO pudo ser creada")
        
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
    """Landing page principal - Diseño inspirado en Calm.com"""
    return render_template('landing.html')

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

@app.route('/participant-access')
def participant_access():
    """Servir la página de acceso específica para participantes"""
    return render_template('participant_access.html')

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
        username = data.get('username') or data.get('email')  # Aceptar username o email
        password = data.get('password')
        
        if not username or not password:
            logger.warning(f"Login attempt with missing credentials from {request.remote_addr}")
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
            
            logger.info(f"Successful login for user {user.username} (ID: {user.id}, Role: {user.role}) from {request.remote_addr}")
            
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
                'redirect': get_dashboard_url(user.role)
            }), 200
        else:
            logger.warning(f"Failed login attempt for username '{username}' from {request.remote_addr}")
            return jsonify({'error': 'Credenciales inválidas o cuenta desactivada'}), 401
            
    except Exception as e:
        logger.error(f"Error in api_login: {str(e)}")
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/logout')
def logout_page():
    """Logout y redirección a la página principal"""
    user_info = f"user {current_user.username} (ID: {current_user.id})" if current_user.is_authenticated else "anonymous user"
    logger.info(f"Logout for {user_info}")
    
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
    logger.info(f"API logout for user {current_user.username} (ID: {current_user.id})")
    
    logout_user()
    # Limpiar sesiones temporales si existen
    session.pop('temp_coachee_id', None)
    session.pop('temp_coachee_token', None)
    session.clear()
    return jsonify({'success': True, 'message': 'Sesión cerrada exitosamente'}), 200

@app.route('/api/register', methods=['POST'])
def api_register():
    """Registro de nuevos usuarios (solo coachees por defecto) con validación mejorada"""
    try:
        data = request.get_json()
        
        # Validar que se recibió JSON
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar datos requeridos
        required_fields = ['username', 'email', 'password', 'full_name']
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        username = str(data['username']).strip()
        email = str(data['email']).strip().lower()
        password = str(data['password'])
        full_name = str(data['full_name']).strip()
        
        # Validaciones adicionales
        if len(username) < 3:
            return jsonify({'error': 'El nombre de usuario debe tener al menos 3 caracteres'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Validar formato de email básico
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        if len(full_name) < 2:
            return jsonify({'error': 'El nombre completo debe tener al menos 2 caracteres'}), 400
        
        # Verificar si el usuario ya existe
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'El nombre de usuario ya está en uso'}), 409
            else:
                return jsonify({'error': 'El email ya está registrado'}), 409
        
        # Crear nuevo usuario con rol especificado o coachee por defecto
        role = data.get('role', 'coachee')
        # Validar que el rol sea válido
        valid_roles = ['coachee', 'coach', 'platform_admin']
        if role not in valid_roles:
            role = 'coachee'
            
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role
        )
        new_user.set_password(password)
        
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
            session.permanent = True
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
    """Crear una invitación para un nuevo coachee y generar credenciales automáticamente"""
    try:
        if current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado: Solo coaches pueden crear invitaciones'}), 403
        
        data = request.get_json()
        full_name = data.get('full_name')
        email = data.get('email')
        message = data.get('message', '')
        
        if not full_name or not email:
            return jsonify({'error': 'Nombre completo y email son requeridos'}), 400
        
        # Validar formato de email básico
        if '@' not in email:
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        # Verificar si ya existe un usuario con este email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Ya existe un usuario registrado con este email'}), 400
        
        # Verificar si ya existe una invitación activa para este email
        existing_invitation = Invitation.query.filter_by(
            coach_id=current_user.id,
            email=email,
            is_used=False
        ).first()
        
        if existing_invitation and existing_invitation.is_valid():
            return jsonify({'error': 'Ya existe una invitación activa para este email'}), 400
        
        # GENERAR CREDENCIALES AUTOMÁTICAMENTE
        import re
        import secrets
        import string
        
        # Generar username basado en el email (parte antes del @)
        base_username = re.sub(r'[^a-zA-Z0-9]', '', email.split('@')[0])
        username = base_username.lower()
        
        # Asegurar que el username sea único
        counter = 1
        original_username = username
        while User.query.filter_by(username=username).first():
            username = f"{original_username}{counter}"
            counter += 1
        
        # Generar contraseña segura
        password_chars = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(password_chars) for _ in range(8))
        
        # Crear el usuario coachee inmediatamente
        new_coachee = User(
            username=username,
            email=email,
            full_name=full_name,
            role='coachee',
            coach_id=current_user.id,
            is_active=True
        )
        new_coachee.set_password(password)
        
        db.session.add(new_coachee)
        db.session.flush()  # Para obtener el ID
        
        # Crear token de invitación
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=30)  # Válida por 30 días
        
        new_invitation = Invitation(
            coach_id=current_user.id,
            email=email,
            full_name=full_name,
            token=token,
            expires_at=expires_at,
            coachee_id=new_coachee.id,  # Vincular con el usuario creado
            message=message
        )
        
        db.session.add(new_invitation)
        db.session.commit()
        
        # Generar URL de acceso directo (ya puede hacer login)
        base_url = request.url_root.rstrip('/')
        login_url = f"{base_url}/login?role=coachee"
        
        return jsonify({
            'success': True,
            'message': f'Coachee creado e invitación enviada para {full_name}',
            'coachee': {
                'id': new_coachee.id,
                'username': username,
                'email': email,
                'full_name': full_name,
                'password': password,  # Se incluye para mostrar al coach
                'login_url': login_url
            },
            'invitation': {
                'id': new_invitation.id,
                'token': token,
                'expires_at': expires_at.isoformat(),
                'message': message
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creando coachee e invitación: {str(e)}'}), 500

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
                'last_assessment': None  # Cambiado de latest_assessment a last_assessment
            }
            
            if latest_assessment:
                coachee_data['last_assessment'] = {
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
        'coach_name': 'Sin asignar'  # Default value
    }
    
    # Obtener el coach de forma segura
    try:
        if coachee_user.coach_id:
            coach = User.query.get(coachee_user.coach_id)
            if coach:
                participant_data['coach_name'] = coach.full_name
    except Exception as e:
        print(f"Error obteniendo coach: {e}")
        # Mantener valor por defecto
    
    # Buscar el token de invitación (si existe) - VERSIÓN SIMPLIFICADA
    invitation_token = session.get('temp_coachee_token')  # Solo desde sesión temporal
    
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

# ====================================================
# MANEJADORES DE ERRORES
# ====================================================

@app.errorhandler(404)
def not_found_error(error):
    """Manejo de errores 404 - Página no encontrada"""
    logger.warning(f"404 Error: {request.url} not found. User: {current_user.id if current_user.is_authenticated else 'Anonymous'}")
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Endpoint no encontrado',
            'status_code': 404,
            'path': request.path
        }), 404
    
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Página no encontrada",
                         error_description="La página que buscas no existe o ha sido movida."), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500 - Error interno del servidor"""
    logger.error(f"500 Error: {str(error)}. URL: {request.url}. User: {current_user.id if current_user.is_authenticated else 'Anonymous'}")
    db.session.rollback()
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Error interno del servidor',
            'status_code': 500,
            'message': 'Ocurrió un error inesperado. Por favor, inténtalo de nuevo.'
        }), 500
    
    return render_template('error.html',
                         error_code=500,
                         error_message="Error interno del servidor",
                         error_description="Ocurrió un error inesperado. Nuestro equipo ha sido notificado."), 500

@app.errorhandler(403)
def forbidden_error(error):
    """Manejo de errores 403 - Acceso prohibido"""
    logger.warning(f"403 Error: Access denied to {request.url}. User: {current_user.id if current_user.is_authenticated else 'Anonymous'}")
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Acceso prohibido',
            'status_code': 403,
            'message': 'No tienes permisos para acceder a este recurso.'
        }), 403
    
    return render_template('error.html',
                         error_code=403,
                         error_message="Acceso prohibido",
                         error_description="No tienes permisos para acceder a esta página."), 403

@app.errorhandler(401)
def unauthorized_error(error):
    """Manejo de errores 401 - No autorizado"""
    logger.warning(f"401 Error: Unauthorized access to {request.url}")
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Autenticación requerida',
            'status_code': 401,
            'message': 'Debes iniciar sesión para acceder a este recurso.'
        }), 401
    
    return redirect(url_for('dashboard_selection'))

@app.errorhandler(400)
def bad_request_error(error):
    """Manejo de errores 400 - Solicitud incorrecta"""
    logger.warning(f"400 Error: Bad request to {request.url}. Error: {str(error)}")
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Solicitud incorrecta',
            'status_code': 400,
            'message': 'Los datos enviados no son válidos.'
        }), 400
    
    return render_template('error.html',
                         error_code=400,
                         error_message="Solicitud incorrecta",
                         error_description="Los datos enviados no son válidos."), 400

# Logging de requests para debugging
@app.before_request
def log_request_info():
    """Log de información de requests para debugging"""
    if not request.path.startswith('/static/'):  # No loggear recursos estáticos
        logger.debug(f"Request: {request.method} {request.path} from {request.remote_addr}")
        if request.is_json and request.method in ['POST', 'PUT', 'PATCH']:
            # Log solo los campos no sensibles
            data = request.get_json() or {}
            safe_data = {k: v for k, v in data.items() if k not in ['password', 'current_password', 'new_password']}
            logger.debug(f"Request data: {safe_data}")

@app.after_request
def log_response_info(response):
    """Log de información de responses"""
    if not request.path.startswith('/static/'):
        logger.debug(f"Response: {response.status_code} for {request.method} {request.path}")
        if response.status_code >= 400:
            logger.warning(f"Error response: {response.status_code} for {request.method} {request.path}")
    return response

# ==========================================
# PUNTO DE ENTRADA PRINCIPAL
# ==========================================

if __name__ == '__main__':
    # Inicializar la base de datos si no existe
    try:
        with app.app_context():
            db.create_all()
            
            # Crear admin por defecto si no existe
            admin = User.query.filter_by(role='platform_admin').first()
            if not admin:
                admin_user = User(
                    username='admin',
                    email='admin@assessmentplatform.com',
                    password_hash=generate_password_hash('admin123'),
                    role='platform_admin',
                    is_active=True
                )
                db.session.add(admin_user)
                db.session.commit()
                logger.info("✅ Usuario admin creado: admin/admin123")
            
            logger.info("✅ Base de datos inicializada correctamente")
    except Exception as e:
        logger.error(f"❌ Error inicializando base de datos: {e}")
    
    # Configuración del servidor
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info(f"🚀 Iniciando Assessment Platform en http://{host}:{port}")
    logger.info(f"🎯 Landing Page disponible en: http://{host}:{port}/")
    logger.info(f"🎛️ Dashboard disponible en: http://{host}:{port}/dashboard-selection")
    
    # Ejecutar la aplicación
    app.run(
        host=host, 
        port=port, 
        debug=debug,
        threaded=True
    )