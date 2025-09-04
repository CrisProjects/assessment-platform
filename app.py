#!/usr/bin/env python3
"""
Aplicación Flask para plataforma de evaluación de asertividad
"""
from dotenv import load_dotenv
load_dotenv()

# Imports principales
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func, desc, inspect, text
from logging.handlers import RotatingFileHandler
import os, secrets, re, logging, string

# Configuración global
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'
DEFAULT_ASSESSMENT_ID = 1
LIKERT_SCALE_MIN, LIKERT_SCALE_MAX = 1, 5

# Configurar logging
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper())
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurar archivo de log si se especifica
if (log_file := os.environ.get('LOG_FILE')) and not IS_PRODUCTION:
    handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=3)
    handler.setLevel(LOG_LEVEL)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    logger.info(f"Logging configurado con archivo: {log_file}")

logger.info(f"Logging iniciado - Nivel: {logging.getLevelName(LOG_LEVEL)}, Producción: {IS_PRODUCTION}")

# Configuración de Flask
app = Flask(__name__)

# Configurar SECRET_KEY
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    if os.environ.get('FLASK_ENV') == 'development' or os.environ.get('RAILWAY_ENVIRONMENT') == 'development':
        SECRET_KEY = secrets.token_hex(32)
        logger.warning("⚠️ DEVELOPMENT: Usando SECRET_KEY generada aleatoriamente")
    elif os.environ.get('RAILWAY_ENVIRONMENT'):
        SECRET_KEY = 'railway-emergency-key-assessment-platform-2025'
        logger.warning("⚠️ RAILWAY: Usando SECRET_KEY de emergencia")
    else:
        raise ValueError("SECRET_KEY environment variable is required in production")

app.config.update({
    'SECRET_KEY': SECRET_KEY,
    'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL', 'sqlite:///assessments.db').replace('postgres://', 'postgresql://', 1),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'PERMANENT_SESSION_LIFETIME': timedelta(days=30),
    'SESSION_PERMANENT': True,
    'SESSION_COOKIE_SECURE': IS_PRODUCTION,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'REMEMBER_COOKIE_DURATION': timedelta(days=30),
    'REMEMBER_COOKIE_SECURE': IS_PRODUCTION,
    'REMEMBER_COOKIE_HTTPONLY': True
})

# Configurar CORS
env_origins = [origin.strip() for origin in os.environ.get('ALLOWED_ORIGINS', '').split(',') if origin.strip()]
default_origins = [
    'http://localhost:3000', 'http://127.0.0.1:3000',
    'https://assessment-platform-1nuo.onrender.com',
    'https://assessment-platform-final.vercel.app',
    'https://assessment-platform-deploy.vercel.app'
]
if not IS_PRODUCTION:
    default_origins.extend(['http://localhost:5002', 'http://127.0.0.1:5002'])

allowed_origins = list(set(env_origins + default_origins))
CORS(app, origins=allowed_origins, supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Origin', 'Accept'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Inicialización de extensiones
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'dashboard_selection'  # type: ignore
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'info'

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.'}), 401
    
    if request.path.startswith(('/platform-admin', '/admin')):
        return redirect(url_for('admin_login_page'))
    elif request.path.startswith('/coach'):
        return redirect(url_for('coach_login_page'))
    return redirect(url_for('dashboard_selection'))

# Modelos de base de datos
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    original_password = db.Column(db.String(120), nullable=True)  # Solo para coachees recién creados
    full_name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='coachee', index=True)
    active = db.Column(db.Boolean, default=True, index=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime, index=True)
    
    # Relaciones
    coach = db.relationship('User', remote_side=[id], backref='coachees')
    assessments = db.relationship('AssessmentResult', foreign_keys='AssessmentResult.user_id', backref='user', lazy=True)

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return self.password_hash and check_password_hash(self.password_hash, password)
    
    @property
    def is_active(self):  # type: ignore
        return self.active
    
    @is_active.setter
    def is_active(self, value):  # type: ignore
        self.active = value
    
    @property
    def is_platform_admin(self): return self.role == 'platform_admin'
    
    @property
    def is_coach(self): return self.role == 'coach'
    
    @property
    def is_coachee(self): return self.role == 'coachee'

class Assessment(db.Model):
    __tablename__ = 'assessment'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True)
    
    questions = db.relationship('Question', backref='assessment', lazy=True, cascade='all, delete-orphan')
    results = db.relationship('AssessmentResult', backref='assessment_ref', lazy=True)

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())

class Question(db.Model):
    __tablename__ = 'question'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), default='likert')
    order = db.Column(db.Integer, index=True)
    dimension = db.Column(db.String(100))  # Dimensión para análisis
    is_active = db.Column(db.Boolean, default=True)
    
    responses = db.relationship('Response', backref='question', lazy=True)

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

class AssessmentResult(db.Model):
    __tablename__ = 'assessment_result'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    score = db.Column(db.Float)
    total_questions = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    result_text = db.Column(db.Text)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    invitation_id = db.Column(db.Integer, db.ForeignKey('invitation.id'), nullable=True, index=True)
    participant_name = db.Column(db.String(200), nullable=True)
    participant_email = db.Column(db.String(120), nullable=True)
    dimensional_scores = db.Column(db.JSON, nullable=True)
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='supervised_assessments')
    invitation = db.relationship('Invitation', backref='assessment_results')
    
    __table_args__ = (
        db.Index('idx_user_assessment', 'user_id', 'assessment_id'),
        db.Index('idx_coach_completed', 'coach_id', 'completed_at'),
    )

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.completed_at = kwargs.get('completed_at', datetime.utcnow())

class Response(db.Model):
    __tablename__ = 'response'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False, index=True)
    selected_option = db.Column(db.Integer)
    assessment_result_id = db.Column(db.Integer, db.ForeignKey('assessment_result.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.Index('idx_user_question', 'user_id', 'question_id'),)

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
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='sent_invitations')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_invitation')
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())
    
    def is_valid(self):
        return self.expires_at and not self.is_used and datetime.utcnow() < self.expires_at
    
    def mark_as_used(self):
        self.is_used = True
        self.used_at = datetime.utcnow()

class Task(db.Model):
    __tablename__ = 'task'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(20), default='medium')
    due_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='assigned_tasks')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_tasks')
    progress_entries = db.relationship('TaskProgress', backref='task', lazy=True, cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        now = datetime.utcnow()
        self.created_at = kwargs.get('created_at', now)
        self.updated_at = kwargs.get('updated_at', now)

class TaskProgress(db.Model):
    __tablename__ = 'task_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    progress_percentage = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    updated_by_user = db.relationship('User', backref='task_updates')

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Funciones auxiliares optimizadas
def get_current_coachee():
    """Obtiene el usuario coachee actual"""
    # PRIMERO: Verificar sesión independiente de coachee (método principal)
    if coachee_user_id := session.get('coachee_user_id'):
        user = db.session.get(User, coachee_user_id)
        if user and user.role == 'coachee':
            return user
    
    # SEGUNDO: Verificar Flask-Login (solo si es seguro acceder)
    try:
        if current_user.is_authenticated and current_user.role == 'coachee':
            return current_user
    except Exception:
        # Si hay error accediendo a current_user, continuar con otros métodos
        pass
    
    # TERCERO: Verificar sesión temporal de coachee
    if temp_coachee_id := session.get('temp_coachee_id'):
        return db.session.get(User, temp_coachee_id)
    return None

def create_decorator(required_condition, error_message, redirect_func=None):
    """Factory para crear decoradores de autorización"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not required_condition():
                if request.path.startswith('/api/'):
                    return jsonify({'error': error_message}), 401 if 'Autenticación' in error_message else 403
                return redirect_func() if redirect_func else redirect(url_for('dashboard_selection'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Decoradores de autorización optimizados
coachee_required = create_decorator(
    lambda: get_current_coachee(),
    'Sesión expirada. Por favor, inicia sesión nuevamente.'
)

def coachee_api_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (coachee_user := get_current_coachee()):
            return jsonify({'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.'}), 401
        kwargs['current_coachee'] = coachee_user
        return f(*args, **kwargs)
    return decorated_function

def coach_session_required(f):
    """Decorador específico para APIs de coach que valida sesión independiente"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        coach_user_id = session.get('coach_user_id')
        if not coach_user_id:
            return jsonify({'error': 'Sesión de coach expirada. Por favor, inicia sesión nuevamente.'}), 401
        
        # Verificar que el usuario existe y es coach
        coach_user = User.query.get(coach_user_id)
        if not coach_user or coach_user.role != 'coach':
            session.pop('coach_user_id', None)
            return jsonify({'error': 'Usuario de coach inválido.'}), 401
        
        # Establecer current_user para esta petición sin usar Flask-Login
        g.current_user = coach_user
        return f(*args, **kwargs)
    return decorated_function

def coachee_session_required(f):
    """Decorador específico para APIs de coachee que valida sesión independiente"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        coachee_user_id = session.get('coachee_user_id')
        if not coachee_user_id:
            return jsonify({'error': 'Sesión de coachee expirada. Por favor, inicia sesión nuevamente.'}), 401
        
        # Verificar que el usuario existe y es coachee
        coachee_user = User.query.get(coachee_user_id)
        if not coachee_user or coachee_user.role != 'coachee':
            session.pop('coachee_user_id', None)
            return jsonify({'error': 'Usuario de coachee inválido.'}), 401
        
        # Establecer current_user para esta petición sin usar Flask-Login
        g.current_user = coachee_user
        return f(*args, **kwargs)
    return decorated_function

def either_session_required(f):
    """Decorador que permite tanto sesión de coach como de coachee"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = None
        
        # Verificar sesión de coach
        if 'coach_user_id' in session:
            coach_id = session['coach_user_id']
            user = User.query.get(coach_id)
            if user and user.role == 'coach':
                current_user = user
        
        # Si no hay sesión de coach, verificar sesión de coachee
        if not current_user and 'coachee_user_id' in session:
            coachee_id = session['coachee_user_id']
            user = User.query.get(coachee_id)
            if user and user.role == 'coachee':
                current_user = user
        
        if not current_user:
            return jsonify({'error': 'No autorizado. Debe iniciar sesión.'}), 401
        
        # Establecer current_user para esta petición sin usar Flask-Login
        g.current_user = current_user
        
        return f(*args, **kwargs)
    return decorated_function

# Helper function para acceder al current_user desde g o Flask-Login
def get_current_user():
    """Obtiene el usuario actual desde g.current_user o Flask-Login current_user"""
    if hasattr(g, 'current_user'):
        return g.current_user
    return current_user

# Override current_user con nuestro sistema de sesiones independientes
@app.before_request
def load_current_user():
    """Cargar el usuario actual desde nuestras sesiones independientes"""
    # Limpiar g.current_user al inicio de cada request
    g.current_user = None
    
    # No establecer g.current_user aquí para evitar conflictos.
    # Cada decorador específico (@coach_session_required, @coachee_session_required) 
    # será responsable de establecer g.current_user basado en su sesión específica.

admin_required = create_decorator(
    lambda: current_user.is_authenticated and current_user.role == 'platform_admin',
    'Acceso denegado. Solo administradores pueden acceder a esta función.'
)

coach_required = create_decorator(
    lambda: current_user.is_authenticated and current_user.role == 'coach',
    'Acceso denegado. Solo coaches pueden acceder a esta función.'
)

# Inicialización automática de base de datos
def auto_initialize_database():
    """Inicialización automática completa para producción"""
    try:
        logger.info("🚀 AUTO-INICIALIZACIÓN: Verificando base de datos...")
        
        # Esperar un momento en caso de PostgreSQL
        import time
        time.sleep(1)
        
        db.create_all()
        logger.info("✅ AUTO-INIT: db.create_all() ejecutado")
        
        # Usar try-except para inspector en caso de problemas con PostgreSQL
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"📋 AUTO-INIT: Tablas encontradas: {tables}")
        except Exception as e:
            logger.warning(f"⚠️ AUTO-INIT: No se pudo inspeccionar tablas: {e}")
            tables = ['user']  # Asumir que la tabla existe
        
        # Verificar tablas críticas
        required_tables = ['user', 'task', 'task_progress']
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            logger.warning(f"🔧 AUTO-INIT: Tablas faltantes: {missing_tables}, creando...")
            db.create_all()
            time.sleep(2)
            
            # Verificar nuevamente
            try:
                inspector = inspect(db.engine)
                tables = inspector.get_table_names()
                logger.info(f"📋 AUTO-INIT: Tablas después de crear: {tables}")
            except Exception as e:
                logger.warning(f"⚠️ AUTO-INIT: Error verificando tablas: {e}")
        
        if 'user' in tables:
            logger.info("✅ AUTO-INIT: Tabla 'user' confirmada")
            
            # Crear usuario admin si no existe
            admin_exists = User.query.filter_by(username='admin').first()
            if not admin_exists:
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
                logger.info("✅ AUTO-INIT: Usuario admin creado correctamente")
            else:
                logger.info("ℹ️ AUTO-INIT: Usuario admin ya existe")
                # Verificar contraseña
                if admin_exists.check_password('admin123'):
                    logger.info("✅ AUTO-INIT: Contraseña admin verificada")
                else:
                    logger.warning("🔧 AUTO-INIT: Actualizando contraseña admin")
                    admin_exists.set_password('admin123')
                    db.session.commit()
                
            # Crear usuario coach si no existe
            coach_exists = User.query.filter_by(username='coach').first()
            if not coach_exists:
                logger.info("👤 AUTO-INIT: Creando usuario coach...")
                coach_user = User(
                    username='coach',
                    email='coach@assessment.com',
                    full_name='Coach Principal',
                    role='coach'
                )
                coach_user.set_password('coach123')
                db.session.add(coach_user)
                db.session.commit()
                logger.info("✅ AUTO-INIT: Usuario coach creado correctamente")
            else:
                logger.info("ℹ️ AUTO-INIT: Usuario coach ya existe")
                # Verificar contraseña
                if coach_exists.check_password('coach123'):
                    logger.info("✅ AUTO-INIT: Contraseña coach verificada")
                else:
                    logger.warning("🔧 AUTO-INIT: Actualizando contraseña coach")
                    coach_exists.set_password('coach123')
                    db.session.commit()
        
        # Inicializar assessment de asertividad
        if not Assessment.query.filter_by(id=1).first():
            logger.info("📝 AUTO-INIT: Creando assessment de asertividad...")
            assessment = Assessment(
                id=1,
                title='Evaluación de Asertividad',
                description='Evaluación completa de habilidades asertivas en diferentes situaciones',
                is_active=True
            )
            db.session.add(assessment)
            db.session.commit()
            logger.info("✅ AUTO-INIT: Assessment de asertividad creado")
        
        # Crear preguntas de asertividad (20 preguntas para análisis dimensional completo)
        if Question.query.filter_by(assessment_id=DEFAULT_ASSESSMENT_ID).count() == 0:
            logger.info("❓ AUTO-INIT: Creando 20 preguntas de asertividad...")
            
            questions = [
                # Comunicación (1-4)
                "Cuando alguien me crítica injustamente, expreso mi desacuerdo de manera calmada y directa.",
                "Me resulta fácil iniciar conversaciones con personas que no conozco bien.",
                "Puedo expresar mis sentimientos de manera clara y directa cuando es necesario.",
                "Soy capaz de dar mi opinión en reuniones o grupos sin sentir ansiedad excesiva.",
                
                # Derechos (5-8)
                "Puedo decir 'no' a las peticiones de otros sin sentirme culpable.",
                "Defiendo mis derechos sin agredir a los demás.",
                "Me siento cómodo/a pidiendo lo que necesito o merezco.",
                "Soy capaz de mantener mis límites personales incluso bajo presión.",
                
                # Opiniones (9-12)
                "Expreso mis opiniones abiertamente, incluso cuando difieren de las de otros.",
                "Puedo estar en desacuerdo con alguien sin atacar su persona.",
                "Me siento cómodo/a expresando mis ideas en situaciones de debate.",
                "Soy capaz de mantener mi posición cuando creo que tengo razón.",
                
                # Conflictos (13-16)
                "Cuando estoy en desacuerdo con algo, lo digo de manera respetuosa.",
                "Puedo manejar conflictos de manera constructiva sin evitarlos.",
                "Soy capaz de confrontar situaciones difíciles cuando es necesario.",
                "Puedo negociar y encontrar soluciones que beneficien a ambas partes.",
                
                # Autoconfianza (17-20)
                "Me resulta fácil pedir ayuda cuando la necesito.",
                "Puedo dar retroalimentación constructiva sin herir los sentimientos de otros.",
                "Me siento cómodo/a expresando mis necesidades y deseos.",
                "Confío en mi capacidad para manejar situaciones sociales complejas."
            ]
            
            # Mapear cada pregunta a su dimensión correspondiente
            dimension_mapping = [
                'Comunicación', 'Comunicación', 'Comunicación', 'Comunicación',  # 1-4
                'Derechos', 'Derechos', 'Derechos', 'Derechos',  # 5-8
                'Opiniones', 'Opiniones', 'Opiniones', 'Opiniones',  # 9-12
                'Conflictos', 'Conflictos', 'Conflictos', 'Conflictos',  # 13-16
                'Autoconfianza', 'Autoconfianza', 'Autoconfianza', 'Autoconfianza'  # 17-20
            ]
            
            for i, text in enumerate(questions, 1):
                question = Question(
                    assessment_id=DEFAULT_ASSESSMENT_ID,
                    text=text,
                    question_type='likert',
                    order=i,
                    dimension=dimension_mapping[i-1]  # Ajustar índice para el mapeo
                )
                db.session.add(question)
            
            db.session.commit()
            logger.info(f"✅ AUTO-INIT: {len(questions)} preguntas de asertividad creadas con dimensiones")
        
        # Verificar coaches existentes
        coach_count = User.query.filter_by(role='coach').count()
        logger.info(f"✅ AUTO-INIT: {coach_count} coaches encontrados en total")
        
        # Crear coachee de prueba
        if not User.query.filter_by(email='coachee@assessment.com').first():
            logger.info("👤 AUTO-INIT: Creando usuario coachee de prueba...")
            coachee_user = User(
                username='coachee',
                email='coachee@assessment.com',
                full_name='Coachee de Prueba',
                role='coachee'
            )
            coachee_user.set_password('coachee123')
            db.session.add(coachee_user)
            db.session.commit()
            create_demo_data_for_coachee(coachee_user)
            logger.info("✅ AUTO-INIT: Usuario coachee creado")
        
        # Crear evaluaciones adicionales
        create_additional_assessments()
        
        logger.info("🎉 AUTO-INIT: Inicialización completa finalizada")
        return True
        
    except Exception as e:
        logger.error(f"❌ AUTO-INIT: Error en inicialización automática: {e}")
        return False

def create_additional_assessments():
    """Crear evaluaciones adicionales para demostrar la funcionalidad - Optimizado para Railway"""
    try:
        logger.info("🔧 ASSESSMENTS: Creando evaluaciones adicionales (Railway optimizado)...")
        
        # Verificar conexión de base de datos primero
        try:
            from sqlalchemy import text as sql_text
            db.session.execute(sql_text("SELECT 1"))
            logger.info("✅ ASSESSMENTS: Conexión a base de datos verificada")
        except Exception as db_error:
            logger.error(f"❌ ASSESSMENTS: Error de conexión a base de datos: {db_error}")
            return False
        
        # Assessment 2: DISC (Personalidad) - Con transacciones individuales
        try:
            if not Assessment.query.filter_by(id=2).first():
                disc_assessment = Assessment(
                    id=2,
                    title='Evaluación DISC de Personalidad',
                    description='Identifica tu estilo de personalidad predominante: Dominante, Influyente, Estable o Concienzudo',
                    is_active=True
                )
                db.session.add(disc_assessment)
                db.session.flush()
                logger.info("✅ ASSESSMENTS: Assessment DISC creado")
                
                # Preguntas DISC
                disc_questions = [
                    "Me gusta tomar decisiones rápidas y asumir riesgos",
                    "Prefiero trabajar en equipo y motivar a otros",
                    "Valoro la estabilidad y la armonía en el trabajo",
                    "Me enfoco en los detalles y la precisión",
                    "Soy directo al comunicar mis ideas",
                    "Disfruto conocer gente nueva y socializar",
                    "Prefiero rutinas establecidas y predecibles",
                    "Analizo cuidadosamente antes de tomar decisiones",
                    "Me siento cómodo liderando proyectos desafiantes",
                    "Soy optimista y entusiasta con nuevas ideas",
                    "Evito conflictos y busco consenso",
                    "Sigo procedimientos y normas establecidas",
                    "Actúo con determinación para alcanzar objetivos",
                    "Inspiro confianza y genero entusiasmo en otros",
                    "Soy leal y comprometido con mi equipo",
                    "Busco perfección en mi trabajo"
                ]
                
                disc_dimensions = [
                    'Dominante', 'Influyente', 'Estable', 'Concienzudo',
                    'Dominante', 'Influyente', 'Estable', 'Concienzudo',
                    'Dominante', 'Influyente', 'Estable', 'Concienzudo',
                    'Dominante', 'Influyente', 'Estable', 'Concienzudo'
                ]
                
                for i, text in enumerate(disc_questions, 1):
                    question = Question(
                        assessment_id=2,
                        text=text,
                        question_type='likert',
                        order=i,
                        dimension=disc_dimensions[i-1]
                    )
                    db.session.add(question)
                
                db.session.commit()
                logger.info("✅ ASSESSMENTS: Preguntas DISC creadas")
            else:
                logger.info("ℹ️ ASSESSMENTS: Assessment DISC ya existe")
        except Exception as disc_error:
            logger.error(f"❌ ASSESSMENTS: Error creando DISC: {disc_error}")
            db.session.rollback()
        
        # Assessment 3: Inteligencia Emocional - Con transacciones individuales
        try:
            if not Assessment.query.filter_by(id=3).first():
                eq_assessment = Assessment(
                    id=3,
                    title='Evaluación de Inteligencia Emocional',
                    description='Mide tu capacidad para reconocer, entender y manejar emociones propias y ajenas',
                    is_active=True
                )
                db.session.add(eq_assessment)
                db.session.flush()
                logger.info("✅ ASSESSMENTS: Assessment de Inteligencia Emocional creado")
                
                # Preguntas de Inteligencia Emocional
                eq_questions = [
                    "Reconozco fácilmente mis propias emociones",
                    "Entiendo qué causa mis cambios de humor",
                    "Soy consciente de mis reacciones emocionales",
                    "Puedo controlar mis emociones en situaciones estresantes",
                    "Mantengo la calma bajo presión",
                    "Puedo motivarme a mí mismo para lograr objetivos",
                    "Reconozco las emociones de otras personas",
                    "Entiendo los sentimientos de los demás",
                    "Soy empático con las experiencias de otros",
                    "Manejo bien las relaciones interpersonales",
                    "Resuelvo conflictos de manera efectiva",
                    "Influyo positivamente en otros"
                ]
                
                eq_dimensions = [
                    'Autoconciencia', 'Autoconciencia', 'Autoconciencia',
                    'Autorregulación', 'Autorregulación', 'Automotivación',
                    'Empatía', 'Empatía', 'Empatía',
                    'Habilidades Sociales', 'Habilidades Sociales', 'Habilidades Sociales'
                ]
                
                for i, text in enumerate(eq_questions, 1):
                    question = Question(
                        assessment_id=3,
                        text=text,
                        question_type='likert',
                        order=i,
                        dimension=eq_dimensions[i-1]
                    )
                    db.session.add(question)
                
                db.session.commit()
                logger.info("✅ ASSESSMENTS: Preguntas de Inteligencia Emocional creadas")
            else:
                logger.info("ℹ️ ASSESSMENTS: Assessment de Inteligencia Emocional ya existe")
        except Exception as eq_error:
            logger.error(f"❌ ASSESSMENTS: Error creando Inteligencia Emocional: {eq_error}")
            db.session.rollback()
        
        # Assessment 4: Liderazgo - Con transacciones individuales
        try:
            if not Assessment.query.filter_by(id=4).first():
                leadership_assessment = Assessment(
                    id=4,
                    title='Evaluación de Habilidades de Liderazgo',
                    description='Evalúa tus competencias de liderazgo y capacidad para dirigir equipos',
                    is_active=True
                )
                db.session.add(leadership_assessment)
                db.session.flush()
                logger.info("✅ ASSESSMENTS: Assessment de Liderazgo creado")
                
                # Preguntas de Liderazgo
                leadership_questions = [
                    "Inspiro confianza en mi equipo",
                    "Comunico la visión de manera clara y convincente",
                    "Tomo decisiones difíciles cuando es necesario",
                    "Delego responsabilidades de manera efectiva",
                    "Proporciono retroalimentación constructiva",
                    "Desarrollo las habilidades de mi equipo",
                    "Me adapto rápidamente a los cambios",
                    "Innovo y busco nuevas oportunidades",
                    "Mantengo la integridad en todas mis acciones",
                    "Asumo responsabilidad por los resultados del equipo"
                ]
                
                leadership_dimensions = [
                    'Inspiración', 'Comunicación', 'Toma de Decisiones',
                    'Delegación', 'Desarrollo de Talento', 'Desarrollo de Talento',
                    'Adaptabilidad', 'Innovación', 'Integridad', 'Responsabilidad'
                ]
                
                for i, text in enumerate(leadership_questions, 1):
                    question = Question(
                        assessment_id=4,
                        text=text,
                        question_type='likert',
                        order=i,
                        dimension=leadership_dimensions[i-1]
                    )
                    db.session.add(question)
                
                db.session.commit()
                logger.info("✅ ASSESSMENTS: Preguntas de Liderazgo creadas")
            else:
                logger.info("ℹ️ ASSESSMENTS: Assessment de Liderazgo ya existe")
        except Exception as leadership_error:
            logger.error(f"❌ ASSESSMENTS: Error creando Liderazgo: {leadership_error}")
            db.session.rollback()
        
        # Assessment 5: Trabajo en Equipo - Con transacciones individuales
        try:
            if not Assessment.query.filter_by(title="Assessment de Trabajo en Equipo").first():
                teamwork_assessment = Assessment(
                    title="Assessment de Trabajo en Equipo",
                    description="Evaluación de habilidades de colaboración y trabajo en equipo",
                    is_active=True
                )
                db.session.add(teamwork_assessment)
                db.session.flush()
                teamwork_id = teamwork_assessment.id
                logger.info(f"✅ ASSESSMENTS: Assessment de Trabajo en Equipo creado con ID: {teamwork_id}")

                # Preguntas para Trabajo en Equipo
                teamwork_questions = [
                    "Colaboro eficazmente con personas de diferentes personalidades",
                    "Comparto información y recursos con mis compañeros de equipo", 
                    "Escucho activamente las ideas y opiniones de otros",
                    "Apoyo a mis compañeros cuando necesitan ayuda",
                    "Asumo mi responsabilidad en los resultados del equipo",
                    "Contribuyo de manera constructiva en las reuniones de equipo",
                    "Manejo los desacuerdos de manera respetuosa y productiva",
                    "Me adapto fácilmente a los cambios en la dinámica del equipo",
                    "Celebro los éxitos del equipo, no solo los individuales",
                    "Confío en las habilidades y compromiso de mis compañeros",
                    "Comunico de manera clara y oportuna con el equipo",
                    "Busco activamente formas de mejorar el desempeño del equipo"
                ]

                # Dimensiones para Trabajo en Equipo
                teamwork_dimensions = [
                    "Colaboración", "Compartir recursos", "Escucha activa",
                    "Apoyo mutuo", "Responsabilidad compartida", "Participación constructiva",
                    "Manejo de conflictos", "Adaptabilidad", "Espíritu de equipo",
                    "Confianza", "Comunicación efectiva", "Mejora continua"
                ]

                for i, text in enumerate(teamwork_questions, 1):
                    question = Question(
                        assessment_id=teamwork_id,
                        text=text,
                        question_type='likert',
                        order=i,
                        dimension=teamwork_dimensions[i-1]
                    )
                    db.session.add(question)
                
                db.session.commit()
                logger.info("✅ ASSESSMENTS: Preguntas de Trabajo en Equipo creadas")
            else:
                logger.info("ℹ️ ASSESSMENTS: Assessment de Trabajo en Equipo ya existe")
        except Exception as teamwork_error:
            logger.error(f"❌ ASSESSMENTS: Error creando Trabajo en Equipo: {teamwork_error}")
            db.session.rollback()

        # Verificar que todo fue creado correctamente
        try:
            total_assessments = Assessment.query.count()
            logger.info(f"🎉 ASSESSMENTS: Proceso completado. Total de evaluaciones: {total_assessments}")
            return True
        except Exception as verify_error:
            logger.error(f"❌ ASSESSMENTS: Error verificando creación: {verify_error}")
            return False
        
    except Exception as e:
        logger.error(f"❌ ASSESSMENTS: Error general creando evaluaciones adicionales: {e}")
        try:
            db.session.rollback()
        except:
            pass
        return False

def create_demo_data_for_coachee(coachee_user):
    """Crear datos de ejemplo para el coachee"""
    try:
        # Crear evaluaciones de ejemplo
        if not AssessmentResult.query.filter_by(user_id=coachee_user.id).first():
            logger.info("📊 AUTO-INIT: Creando evaluaciones de ejemplo...")
            
            demo_assessments = [
                {
                    'score': 75.5, 'total_questions': 10,
                    'result_text': 'Nivel asertivo moderado. Buena base con áreas de mejora en situaciones de conflicto.',
                    'completed_at': datetime.utcnow() - timedelta(days=7),
                    'dimensional_scores': {'comunicacion': 80, 'derechos': 70, 'opiniones': 75, 'conflictos': 65, 'autoconfianza': 85}
                },
                {
                    'score': 82.0, 'total_questions': 10,
                    'result_text': 'Excelente progreso en asertividad. Mejora notable en manejo de conflictos.',
                    'completed_at': datetime.utcnow() - timedelta(days=3),
                    'dimensional_scores': {'comunicacion': 85, 'derechos': 80, 'opiniones': 80, 'conflictos': 78, 'autoconfianza': 87}
                }
            ]
            
            for data in demo_assessments:
                result = AssessmentResult(user_id=coachee_user.id, assessment_id=1, **data)
                db.session.add(result)
            
            logger.info("✅ AUTO-INIT: Evaluaciones de ejemplo creadas")
        
        # Crear tareas de ejemplo
        if not Task.query.filter_by(coachee_id=coachee_user.id).first():
            logger.info("📋 AUTO-INIT: Creando tareas de ejemplo...")
            
            coach_user = User.query.filter_by(role='platform_admin').first() or User.query.filter_by(role='coach').first()
            if coach_user:
                demo_tasks = [
                    {
                        'title': 'Practicar comunicación asertiva',
                        'description': 'Durante esta semana, practica expresar tus opiniones de manera clara y respetuosa en al menos 3 situaciones diferentes.',
                        'category': 'comunicacion', 'priority': 'high',
                        'due_date': date.today() + timedelta(days=7)
                    },
                    {
                        'title': 'Ejercicio de autoconfianza',
                        'description': 'Identifica 5 fortalezas personales y escribe ejemplos específicos de cómo las has utilizado exitosamente.',
                        'category': 'autoconfianza', 'priority': 'medium',
                        'due_date': date.today() + timedelta(days=5)
                    }
                ]
                
                for task_data in demo_tasks:
                    task = Task(coach_id=coach_user.id, coachee_id=coachee_user.id, **task_data)
                    db.session.add(task)
                
                db.session.flush()
                
                # Agregar progreso inicial
                for task in Task.query.filter_by(coachee_id=coachee_user.id).all():
                    if task.category in ['comunicacion', 'autoconfianza']:
                        progress = TaskProgress(
                            task_id=task.id,
                            status='in_progress',
                            progress_percentage=30 if task.category == 'comunicacion' else 60,
                            notes='Progreso inicial registrado automáticamente',
                            updated_by=coachee_user.id
                        )
                        db.session.add(progress)
                
                logger.info("✅ AUTO-INIT: Tareas de ejemplo creadas")
        
        db.session.commit()
        logger.info("✅ AUTO-INIT: Datos de ejemplo preparados")
        
    except Exception as e:
        logger.error(f"⚠️ AUTO-INIT: Error creando datos de ejemplo: {e}")
        db.session.rollback()

def get_dashboard_url(role):
    """Retorna la URL del dashboard según el rol"""
    urls = {
        'platform_admin': '/platform-admin-dashboard',
        'coach': '/coach-dashboard',
        'coachee': '/coachee-dashboard'
    }
    return urls.get(role, '/coachee-dashboard')

def validate_required_fields(data, required_fields):
    """Valida campos requeridos en los datos"""
    missing_fields = [field for field in required_fields if not data.get(field) or not str(data.get(field)).strip()]
    return missing_fields

def create_user_response(user):
    """Crea respuesta estándar de usuario"""
    return {
        'id': user.id,
        'username': user.username,
        'full_name': user.full_name,
        'email': user.email,
        'role': user.role,
        'coach_id': user.coach_id
    }

def validate_evaluation_visibility(coachee_id, assessment_id=None):
    """
    Valida que las evaluaciones sean visibles para un coachee específico
    
    Args:
        coachee_id (int): ID del coachee a validar
        assessment_id (int, optional): ID específico de evaluación. Si no se proporciona, valida todas.
    
    Returns:
        dict: Resultado de la validación con detalles
    """
    try:
        # Obtener el coachee
        coachee = User.query.get(coachee_id)
        if not coachee:
            return {
                'valid': False,
                'error': 'Coachee no encontrado',
                'details': {'coachee_id': coachee_id}
            }
        
        # Verificar que es un coachee
        if coachee.role != 'coachee':
            return {
                'valid': False,
                'error': f'Usuario no es coachee (rol: {coachee.role})',
                'details': {'user_id': coachee_id, 'role': coachee.role}
            }
        
        # Verificar que tiene coach asignado
        if not coachee.coach_id:
            return {
                'valid': False,
                'error': 'Coachee no tiene coach asignado',
                'details': {'coachee_id': coachee_id, 'coach_id': None}
            }
        
        # Verificar que el coach existe
        coach = User.query.get(coachee.coach_id)
        if not coach or coach.role != 'coach':
            return {
                'valid': False,
                'error': 'Coach asignado no válido',
                'details': {'coach_id': coachee.coach_id, 'coach_exists': coach is not None}
            }
        
        # Obtener evaluaciones completadas
        completed_results = AssessmentResult.query.filter_by(user_id=coachee_id).all()
        completed_assessment_ids = [r.assessment_id for r in completed_results]
        
        # Si se especifica una evaluación, validar solo esa
        if assessment_id:
            assessments_to_check = Assessment.query.filter_by(id=assessment_id).all()
            if not assessments_to_check:
                return {
                    'valid': False,
                    'error': f'Assessment {assessment_id} no encontrado',
                    'details': {'assessment_id': assessment_id}
                }
        else:
            # Validar todas las evaluaciones activas
            assessments_to_check = Assessment.query.filter_by(is_active=True).all()
        
        validation_results = []
        available_count = 0
        
        for assessment in assessments_to_check:
            # Verificar si ya está completada
            is_completed = assessment.id in completed_assessment_ids
            
            # Obtener preguntas activas
            active_questions = Question.query.filter_by(
                assessment_id=assessment.id, 
                is_active=True
            ).count()
            
            assessment_validation = {
                'assessment_id': assessment.id,
                'title': assessment.title,
                'is_active': assessment.is_active,
                'is_completed': is_completed,
                'active_questions_count': active_questions,
                'visible': assessment.is_active and not is_completed and active_questions > 0
            }
            
            if assessment_validation['visible']:
                available_count += 1
            
            validation_results.append(assessment_validation)
        
        return {
            'valid': True,
            'coachee': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'role': coachee.role,
                'coach_id': coachee.coach_id,
                'coach_name': coach.full_name if coach else None
            },
            'total_assessments_checked': len(assessments_to_check),
            'available_assessments_count': available_count,
            'completed_assessments_count': len(completed_assessment_ids),
            'assessments': validation_results,
            'summary': {
                'has_coach': True,
                'coach_valid': True,
                'can_see_evaluations': available_count > 0
            }
        }
        
    except Exception as e:
        logger.error(f"Error validando visibilidad de evaluaciones: {str(e)}", exc_info=True)
        return {
            'valid': False,
            'error': f'Error interno: {str(e)}',
            'details': {'coachee_id': coachee_id, 'assessment_id': assessment_id}
        }

def calculate_assertiveness_score(responses):
    """Calcula puntuación de asertividad basada en respuestas"""
    if not responses:
        return 0, "Sin respuestas disponibles", None
    
    # Manejar tanto formato lista como diccionario
    if isinstance(responses, list):
        # Si es una lista de objetos con question_id y selected_option
        total_score = sum(int(r.get('selected_option', 0)) for r in responses)
        num_responses = len(responses)
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
    else:
        # Si es un diccionario (formato anterior), convertir valores a int
        total_score = sum(int(val) if isinstance(val, (str, int)) else 0 for val in responses.values())
        num_responses = len(responses)
        response_dict = responses
    
    max_possible = num_responses * LIKERT_SCALE_MAX
    percentage = (total_score / max_possible) * 100
    
    # Clasificación por nivel de asertividad
    if percentage >= 80:
        level = "Muy asertivo"
        text = "Excelente nivel de asertividad. Mantienes un equilibrio entre expresar tus necesidades y respetar a otros."
    elif percentage >= 60:
        level = "Asertivo"
        text = "Buen nivel de asertividad. Tienes habilidades sólidas con algunas áreas de mejora."
    elif percentage >= 40:
        level = "Moderadamente asertivo"
        text = "Nivel moderado de asertividad. Hay oportunidades significativas de desarrollo."
    else:
        level = "Poco asertivo"
        text = "Nivel bajo de asertividad. Se recomienda trabajar en el desarrollo de estas habilidades."
    
    # Calcular análisis dimensional basado en las preguntas
    dimensional_scores = calculate_dimensional_scores(response_dict)
    
    return percentage, f"{level}: {text}", dimensional_scores

def calculate_dimensional_scores(response_dict):
    """Calcula puntuaciones por dimensiones de asertividad"""
    
    # Definir qué preguntas corresponden a cada dimensión
    # (Basado en un modelo típico de asertividad)
    dimensions = {
        'comunicacion': [1, 2, 3, 4],  # Habilidades de comunicación
        'derechos': [5, 6, 7, 8],      # Defensa de derechos personales
        'opiniones': [9, 10, 11, 12],  # Expresión de opiniones
        'conflictos': [13, 14, 15, 16], # Manejo de conflictos
        'autoconfianza': [17, 18, 19, 20] # Autoconfianza y autoestima
    }
    
    dimensional_scores = {}
    
    for dimension, question_ids in dimensions.items():
        dimension_total = 0
        dimension_count = 0
        
        for question_id in question_ids:
            if str(question_id) in response_dict:
                # Convertir a int para asegurar suma numérica
                value = response_dict[str(question_id)]
                if isinstance(value, str):
                    value = int(value)
                dimension_total += value
                dimension_count += 1
        
        if dimension_count > 0:
            # Calcular porcentaje para esta dimensión
            max_possible = dimension_count * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
        else:
            # Si no hay respuestas para esta dimensión, usar el promedio general
            total_responses = len(response_dict)
            if total_responses > 0:
                avg_score = sum(response_dict.values()) / total_responses
                avg_percentage = (avg_score / LIKERT_SCALE_MAX) * 100
                dimensional_scores[dimension] = round(avg_percentage, 1)
            else:
                dimensional_scores[dimension] = 0
    
    return dimensional_scores

def calculate_disc_score(responses):
    """Calcula puntuación DISC basada en respuestas y determina estilo predominante"""
    logger.info(f"🎯 CALCULATE_DISC_SCORE: Starting calculation with {len(responses) if responses else 0} responses")
    logger.info(f"🎯 CALCULATE_DISC_SCORE: Raw responses: {responses}")
    
    if not responses:
        return 0, "Sin respuestas disponibles", None

    # Manejar tanto formato lista como diccionario
    if isinstance(responses, list):
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Converted to dict: {response_dict}")
    else:
        response_dict = responses
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Using as dict: {response_dict}")

    # Crear mapeo dinámico de order -> dimensión basado en la base de datos
    try:
        # Obtener el mapeo desde la base de datos
        questions = Question.query.filter_by(assessment_id=2).order_by(Question.order).all()
        order_to_dimension = {}
        question_id_to_order = {}
        
        for question in questions:
            order_to_dimension[question.order] = question.dimension
            question_id_to_order[question.id] = question.order
            
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Order mapping: {order_to_dimension}")
        logger.info(f"🎯 CALCULATE_DISC_SCORE: ID to Order mapping: {question_id_to_order}")
        
    except Exception as e:
        logger.error(f"🎯 CALCULATE_DISC_SCORE: Error creating dynamic mapping: {e}")
        # Fallback a mapeo hardcodeado si falla la consulta
        disc_dimensions = {
            'Dominante': [21, 25, 29, 33],     
            'Influyente': [22, 26, 30, 34],    
            'Estable': [23, 27, 31, 35],       
            'Concienzudo': [24, 28, 32, 36]    
        }
        return calculate_disc_score_legacy(response_dict, disc_dimensions)

    # Agrupar por dimensión usando el mapeo dinámico
    dimension_responses = {}
    
    for question_id_str, response_value in response_dict.items():
        try:
            question_id = int(question_id_str)
            if question_id in question_id_to_order:
                order = question_id_to_order[question_id]
                dimension = order_to_dimension[order]
                
                if dimension not in dimension_responses:
                    dimension_responses[dimension] = []
                dimension_responses[dimension].append(response_value)
                
                logger.info(f"🎯 CALCULATE_DISC_SCORE: Question {question_id} (order {order}) -> {dimension} = {response_value}")
            else:
                logger.warning(f"🎯 CALCULATE_DISC_SCORE: Question {question_id} not found in DISC assessment")
        except ValueError:
            logger.error(f"🎯 CALCULATE_DISC_SCORE: Invalid question_id: {question_id_str}")
    
    # Calcular puntuaciones dimensionales
    dimensional_scores = {}
    
    for dimension, responses_list in dimension_responses.items():
        if responses_list:
            # Calcular porcentaje para esta dimensión
            dimension_total = sum(responses_list)
            max_possible = len(responses_list) * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
            logger.info(f"🎯 CALCULATE_DISC_SCORE: {dimension} = {dimension_total}/{max_possible} = {dimension_percentage}%")
        else:
            dimensional_scores[dimension] = 0
            logger.info(f"🎯 CALCULATE_DISC_SCORE: {dimension} = 0 (no responses found)")
    
    # Determinar estilo predominante
    if dimensional_scores:
        predominant_style = max(dimensional_scores, key=dimensional_scores.get)
        max_score = dimensional_scores[predominant_style]
        
        # Calcular puntuación general como promedio de todas las dimensiones
        overall_score = sum(dimensional_scores.values()) / len(dimensional_scores)
        
        # Generar texto descriptivo basado en el estilo predominante
        style_descriptions = {
            'Dominante': "Estilo Dominante: Orientado a resultados, directo y decidido. Te enfocas en superar desafíos y lograr objetivos.",
            'Influyente': "Estilo Influyente: Sociable, optimista y persuasivo. Te motiva inspirar y conectar con otros.",
            'Estable': "Estilo Estable: Cooperativo, confiable y paciente. Valoras la estabilidad y el trabajo en equipo.",
            'Concienzudo': "Estilo Concienzudo: Analítico, preciso y sistemático. Te enfocas en la calidad y seguir procedimientos."
        }
        
        result_text = style_descriptions.get(predominant_style, "Estilo de personalidad identificado")
        
        # Agregar información sobre puntuaciones secundarias
        sorted_scores = sorted(dimensional_scores.items(), key=lambda x: x[1], reverse=True)
        if len(sorted_scores) > 1 and sorted_scores[1][1] > 60:  # Si la segunda puntuación es alta
            secondary_style = sorted_scores[1][0]
            result_text += f" Con características secundarias del estilo {secondary_style}."
        
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Final result - Score: {round(overall_score, 1)}, Style: {predominant_style}")
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Dimensional scores: {dimensional_scores}")
        
        return round(overall_score, 1), result_text, dimensional_scores
    
    return 0, "No se pudieron calcular las puntuaciones DISC", {}


def calculate_disc_score_legacy(response_dict, disc_dimensions):
    """Función legacy para compatibilidad hacia atrás"""
    dimensional_scores = {}
    
    # Calcular puntuación para cada dimensión DISC
    for dimension, question_ids in disc_dimensions.items():
        dimension_total = 0
        dimension_count = 0
        
        logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: Processing dimension {dimension} with questions {question_ids}")
        
        for question_id in question_ids:
            if str(question_id) in response_dict:
                response_value = response_dict[str(question_id)]
                dimension_total += response_value
                dimension_count += 1
                logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: Question {question_id} = {response_value}")
            else:
                logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: Question {question_id} NOT FOUND in responses")
        
        if dimension_count > 0:
            # Calcular porcentaje para esta dimensión
            max_possible = dimension_count * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
            logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: {dimension} = {dimension_total}/{max_possible} = {dimension_percentage}%")
        else:
            dimensional_scores[dimension] = 0
            logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: {dimension} = 0 (no responses found)")
    
    # Determinar estilo predominante
    if dimensional_scores:
        predominant_style = max(dimensional_scores, key=dimensional_scores.get)
        overall_score = sum(dimensional_scores.values()) / len(dimensional_scores)
        
        style_descriptions = {
            'Dominante': "Estilo Dominante: Orientado a resultados, directo y decidido. Te enfocas en superar desafíos y lograr objetivos.",
            'Influyente': "Estilo Influyente: Sociable, optimista y persuasivo. Te motiva inspirar y conectar con otros.",
            'Estable': "Estilo Estable: Cooperativo, confiable y paciente. Valoras la estabilidad y el trabajo en equipo.",
            'Concienzudo': "Estilo Concienzudo: Analítico, preciso y sistemático. Te enfocas en la calidad y seguir procedimientos."
        }
        
        result_text = style_descriptions.get(predominant_style, "Estilo de personalidad identificado")
        
        return round(overall_score, 1), result_text, dimensional_scores
    
    return 0, "No se pudieron calcular las puntuaciones DISC", {}


def calculate_emotional_intelligence_score(responses):
    """Calcula puntuación de Inteligencia Emocional basada en respuestas y dimensiones específicas"""
    logger.info(f"🎯 CALCULATE_EQ_SCORE: Starting calculation with {len(responses) if responses else 0} responses")
    logger.info(f"🎯 CALCULATE_EQ_SCORE: Raw responses: {responses}")
    
    if not responses:
        return 0, "Sin respuestas disponibles", None

    # Manejar tanto formato lista como diccionario
    if isinstance(responses, list):
        total_score = sum(int(r.get('selected_option', 0)) for r in responses)
        num_responses = len(responses)
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
        logger.info(f"🎯 CALCULATE_EQ_SCORE: Converted to dict: {response_dict}")
    else:
        total_score = sum(int(val) if isinstance(val, (str, int)) else 0 for val in responses.values())
        num_responses = len(responses)
        response_dict = responses
        logger.info(f"🎯 CALCULATE_EQ_SCORE: Using as dict: {response_dict}")

    # Definir qué preguntas corresponden a cada dimensión de Inteligencia Emocional
    # IDs reales en la base de datos (empiezan en 37 para IE)
    eq_dimensions = {
        'Autoconciencia': [37, 38, 39],           # Reconocer propias emociones (3 preguntas)
        'Autorregulación': [40, 41],              # Controlar emociones (2 preguntas)
        'Automotivación': [42],                   # Motivarse a sí mismo (1 pregunta)
        'Empatía': [43, 44, 45],                  # Reconocer emociones ajenas (3 preguntas)
        'Habilidades Sociales': [46, 47, 48]     # Manejar relaciones (3 preguntas)
    }
    
    dimensional_scores = {}
    
    # Calcular puntuación para cada dimensión de IE
    for dimension, question_ids in eq_dimensions.items():
        dimension_total = 0
        dimension_count = 0
        
        logger.info(f"🎯 CALCULATE_EQ_SCORE: Processing dimension {dimension} with questions {question_ids}")
        
        for question_id in question_ids:
            if str(question_id) in response_dict:
                response_value = int(response_dict[str(question_id)])
                dimension_total += response_value
                dimension_count += 1
                logger.info(f"🎯 CALCULATE_EQ_SCORE: Question {question_id} = {response_value}")
            else:
                logger.info(f"🎯 CALCULATE_EQ_SCORE: Question {question_id} NOT FOUND in responses")
        
        if dimension_count > 0:
            # Calcular porcentaje para esta dimensión
            max_possible = dimension_count * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
            logger.info(f"🎯 CALCULATE_EQ_SCORE: {dimension} = {dimension_total}/{max_possible} = {dimension_percentage}%")
        else:
            dimensional_scores[dimension] = 0
            logger.info(f"🎯 CALCULATE_EQ_SCORE: {dimension} = 0 (no responses found)")

    # Calcular puntuación general como promedio de todas las dimensiones
    if dimensional_scores:
        overall_score = sum(dimensional_scores.values()) / len(dimensional_scores)
        
        # Clasificación por nivel de inteligencia emocional
        if overall_score >= 85:
            level = "Muy alta"
            text = "Inteligencia emocional muy alta. Tienes excelente capacidad para reconocer, entender y manejar emociones."
        elif overall_score >= 70:
            level = "Alta"
            text = "Inteligencia emocional alta. Manejas bien las emociones con algunas oportunidades de mejora."
        elif overall_score >= 55:
            level = "Moderada"
            text = "Inteligencia emocional moderada. Hay áreas importantes para desarrollar tu competencia emocional."
        elif overall_score >= 40:
            level = "Baja"
            text = "Inteligencia emocional baja. Se recomienda trabajar en el desarrollo de estas habilidades fundamentales."
        else:
            level = "Muy baja"
            text = "Inteligencia emocional muy baja. Es prioritario desarrollar competencias emocionales básicas."

        # Identificar fortalezas y áreas de mejora
        if dimensional_scores:
            strongest_dimension = max(dimensional_scores, key=dimensional_scores.get)
            weakest_dimension = min(dimensional_scores, key=dimensional_scores.get)
            
            result_text = f"{level}: {text}"
            if dimensional_scores[strongest_dimension] > 70:
                result_text += f" Tu fortaleza principal es {strongest_dimension.lower()}."
            if dimensional_scores[weakest_dimension] < 60:
                result_text += f" Considera desarrollar más tu {weakest_dimension.lower()}."

        logger.info(f"🎯 CALCULATE_EQ_SCORE: Final result - Score: {round(overall_score, 1)}, Level: {level}")
        logger.info(f"🎯 CALCULATE_EQ_SCORE: Dimensional scores: {dimensional_scores}")
        
        return round(overall_score, 1), result_text, dimensional_scores
    
    return 0, "No se pudieron calcular las puntuaciones de Inteligencia Emocional", {}


def generate_disc_recommendations(disc_scores, overall_score):
    """Genera recomendaciones específicas para evaluaciones DISC"""
    recommendations = []
    
    # Identificar estilo dominante
    dominant_style = max(disc_scores, key=disc_scores.get) if disc_scores else 'balanced'
    
    # Recomendaciones por estilo DISC
    style_recommendations = {
        'D': {
            'title': 'Desarrollo para Estilo Dominante',
            'strengths': ['Liderazgo natural', 'Toma de decisiones rápida', 'Orientación a resultados', 'Confianza en situaciones desafiantes'],
            'development': [
                'Practica la paciencia y escucha activa con tu equipo',
                'Desarrolla habilidades de colaboración y trabajo en equipo',
                'Aprende a delegar efectivamente sin microgestionar',
                'Mejora tu capacidad para dar feedback constructivo',
                'Practica la empatía en situaciones interpersonales'
            ]
        },
        'I': {
            'title': 'Desarrollo para Estilo Influyente',
            'strengths': ['Comunicación persuasiva', 'Optimismo contagioso', 'Habilidades sociales', 'Creatividad e innovación'],
            'development': [
                'Desarrolla mayor atención al detalle en tus proyectos',
                'Practica el seguimiento sistemático de tareas y compromisos',
                'Aprende técnicas de organización y gestión del tiempo',
                'Mejora tu capacidad de análisis antes de tomar decisiones',
                'Fortalece habilidades de escucha profunda'
            ]
        },
        'S': {
            'title': 'Desarrollo para Estilo Estable',
            'strengths': ['Confiabilidad y consistencia', 'Trabajo en equipo', 'Paciencia y perseverancia', 'Lealtad organizacional'],
            'development': [
                'Desarrolla mayor confianza para expresar tus ideas',
                'Practica la adaptabilidad ante cambios organizacionales',
                'Fortalece habilidades de liderazgo y toma de iniciativa',
                'Aprende a manejar múltiples prioridades simultáneamente',
                'Mejora tu capacidad de influencia y persuasión'
            ]
        },
        'C': {
            'title': 'Desarrollo para Estilo Concienzudo',
            'strengths': ['Análisis meticuloso', 'Alta calidad de trabajo', 'Pensamiento sistemático', 'Precisión y exactitud'],
            'development': [
                'Desarrolla mayor flexibilidad en procesos y procedimientos',
                'Practica la comunicación clara y directa con otros',
                'Aprende a tomar decisiones con información limitada',
                'Mejora habilidades de networking y relaciones interpersonales',
                'Fortalece tu capacidad de adaptación al cambio'
            ]
        }
    }
    
    # Agregar recomendaciones del estilo dominante
    if dominant_style in style_recommendations:
        style_data = style_recommendations[dominant_style]
        recommendations.extend([
            f"**{style_data['title']}**",
            "",
            "**Tus Fortalezas Naturales:**"
        ])
        for strength in style_data['strengths']:
            recommendations.append(f"• {strength}")
        
        recommendations.extend([
            "",
            "**Áreas de Desarrollo Recomendadas:**"
        ])
        for dev in style_data['development']:
            recommendations.append(f"• {dev}")
    
    # Recomendaciones generales por nivel
    recommendations.extend([
        "",
        "**Plan de Acción de 90 Días:**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• Semana 1-30: Identifica un área de desarrollo y crea un plan específico",
            "• Semana 31-60: Practica nuevas habilidades en situaciones de bajo riesgo",
            "• Semana 61-90: Aplica aprendizajes en desafíos más complejos",
            "• Busca oportunidades de mentoría para otros"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• Semana 1-30: Autoevaluación profunda de fortalezas y oportunidades",
            "• Semana 31-60: Implementa 2-3 nuevas estrategias de comunicación",
            "• Semana 61-90: Solicita feedback regular de colegas y supervisor",
            "• Considera tomar un curso de desarrollo de habilidades interpersonales"
        ])
    else:
        recommendations.extend([
            "• Semana 1-30: Observa y aprende de personas con estilos complementarios",
            "• Semana 31-60: Practica una nueva habilidad cada semana",
            "• Semana 61-90: Busca un mentor o coach para guía personalizada",
            "• Enfócate en desarrollar autoconciencia de tu estilo natural"
        ])
    
    return recommendations

def generate_emotional_intelligence_recommendations(ei_scores, overall_score):
    """Genera recomendaciones específicas para Inteligencia Emocional"""
    recommendations = []
    
    # Mapeo de dimensiones IE
    dimension_names = {
        'autoconciencia': 'Autoconciencia Emocional',
        'autorregulacion': 'Autorregulación',
        'automotivacion': 'Automotivación',
        'empatia': 'Empatía',
        'habilidades_sociales': 'Habilidades Sociales'
    }
    
    # Identificar áreas de oportunidad (< 65%)
    development_areas = {dim: score for dim, score in ei_scores.items() if score < 65}
    
    # Recomendaciones específicas por dimensión
    dimension_recommendations = {
        'autoconciencia': [
            'Practica la meditación mindfulness 10 minutos diarios',
            'Lleva un diario emocional para identificar patrones',
            'Solicita feedback regular sobre tu estado emocional',
            'Realiza autoevaluaciones semanales de tus reacciones emocionales'
        ],
        'autorregulacion': [
            'Aprende técnicas de respiración profunda para momentos de estrés',
            'Practica la pausa de 6 segundos antes de reaccionar',
            'Desarrolla estrategias de manejo del estrés personalizadas',
            'Identifica y evita disparadores emocionales negativos'
        ],
        'automotivacion': [
            'Establece metas SMART claras y revisables',
            'Crea un sistema de recompensas por logros pequeños',
            'Desarrolla una mentalidad de crecimiento ante los desafíos',
            'Practica la visualización positiva de tus objetivos'
        ],
        'empatia': [
            'Practica la escucha activa sin juzgar ni aconsejar',
            'Observa y aprende lenguaje corporal y señales no verbales',
            'Pregunta más sobre los sentimientos de otros',
            'Participa en actividades de voluntariado o servicio comunitario'
        ],
        'habilidades_sociales': [
            'Practica iniciar conversaciones en diferentes contextos',
            'Desarrolla habilidades de resolución de conflictos',
            'Aprende técnicas de comunicación asertiva',
            'Participa en actividades grupales y de networking'
        ]
    }
    
    # Agregar recomendaciones por área de desarrollo
    for dimension, score in development_areas.items():
        dimension_name = dimension_names.get(dimension, dimension)
        recs = dimension_recommendations.get(dimension, [])
        
        recommendations.extend([
            f"**{dimension_name}** (Puntuación: {score}%)",
            "Objetivos de desarrollo:"
        ])
        for rec in recs[:3]:  # Top 3 recomendaciones
            recommendations.append(f"• {rec}")
        recommendations.append("")
    
    # Plan estructurado por nivel
    recommendations.extend([
        "**Plan de Desarrollo Estructurado:**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Nivel Avanzado:** Enfócate en el mentoring y desarrollo de otros",
            "• Lidera iniciativas de bienestar emocional en tu organización",
            "• Desarrolla programas de inteligencia emocional para equipos",
            "• Busca certificaciones en coaching emocional"
        ])
    elif overall_score >= 65:
        recommendations.extend([
            "• **Nivel Intermedio:** Profundiza en áreas específicas de oportunidad",
            "• Práctica diaria de técnicas de inteligencia emocional",
            "• Busca feedback 360° sobre tus habilidades emocionales",
            "• Considera un coach especializado en inteligencia emocional"
        ])
    else:
        recommendations.extend([
            "• **Nivel Básico:** Construye fundamentos sólidos",
            "• Dedica 15 minutos diarios a desarrollo de autoconciencia",
            "• Lee libros especializados en inteligencia emocional",
            "• Practica una habilidad emocional específica cada semana"
        ])
    
    return recommendations

def generate_assertiveness_recommendations(assertiveness_scores, overall_score):
    """Genera recomendaciones específicas para Asertividad"""
    recommendations = []
    
    # Mapeo de dimensiones de asertividad
    dimension_names = {
        'comunicacion': 'Habilidades de Comunicación',
        'derechos': 'Defensa de Derechos Personales',
        'opiniones': 'Expresión de Opiniones',
        'conflictos': 'Manejo de Conflictos',
        'autoconfianza': 'Autoconfianza y Autoestima'
    }
    
    # Identificar dimensiones débiles
    weak_dimensions = {dim: score for dim, score in assertiveness_scores.items() if score < 60}
    
    # Recomendaciones específicas
    dimension_recommendations = {
        'comunicacion': [
            'Practica el contacto visual durante conversaciones importantes',
            'Usa un tono de voz firme pero respetuoso',
            'Aprende técnicas de comunicación no violenta',
            'Desarrolla habilidades de escucha empática'
        ],
        'derechos': [
            'Identifica y enumera tus derechos personales y profesionales',
            'Practica decir "no" sin justificaciones excesivas',
            'Establece límites claros en relaciones personales y laborales',
            'Desarrolla confianza en tu valor y contribuciones'
        ],
        'opiniones': [
            'Participa activamente en reuniones y discusiones grupales',
            'Practica expresar desacuerdo de manera constructiva',
            'Desarrolla argumentos sólidos antes de compartir ideas',
            'Aprende a recibir y dar feedback de manera efectiva'
        ],
        'conflictos': [
            'Aprende técnicas de negociación colaborativa',
            'Practica mantener la calma bajo presión',
            'Enfócate en problemas específicos, no en personalidades',
            'Desarrolla habilidades de mediación y resolución de problemas'
        ],
        'autoconfianza': [
            'Reconoce y celebra tus logros diarios',
            'Practica autoafirmaciones positivas',
            'Desafía pensamientos autolimitantes',
            'Establece metas alcanzables para construir confianza gradualmente'
        ]
    }
    
    # Agregar recomendaciones por dimensión débil
    for dimension, score in weak_dimensions.items():
        dimension_name = dimension_names.get(dimension, dimension)
        recs = dimension_recommendations.get(dimension, [])
        
        recommendations.extend([
            f"**{dimension_name}** (Puntuación: {score}%)",
            "Estrategias de mejora:"
        ])
        for rec in recs:
            recommendations.append(f"• {rec}")
        recommendations.append("")
    
    # Plan de desarrollo por nivel
    recommendations.extend([
        "**Programa de Desarrollo Asertivo:**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Nivel Experto:** Mantén y refina tus habilidades asertivas",
            "• Mentoriza a otros en comunicación asertiva",
            "• Lidera por ejemplo en situaciones complejas",
            "• Busca roles que requieran alta asertividad"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• **Nivel Competente:** Fortalece áreas específicas",
            "• Practica situaciones desafiantes en entorno seguro",
            "• Solicita feedback regular sobre tu comunicación",
            "• Toma cursos avanzados de comunicación asertiva"
        ])
    else:
        recommendations.extend([
            "• **Nivel Desarrollo:** Construye bases sólidas",
            "• Comienza con situaciones de baja complejidad",
            "• Practica técnicas básicas diariamente",
            "• Considera trabajar con un coach o terapeuta"
        ])
    
    return recommendations

def generate_leadership_recommendations(leadership_scores, overall_score):
    """Genera recomendaciones específicas para Liderazgo"""
    recommendations = []
    
    recommendations.extend([
        "**Plan de Desarrollo de Liderazgo**",
        "",
        "**Competencias Clave a Desarrollar:**",
        "• Visión estratégica y comunicación inspiradora",
        "• Desarrollo y empoderamiento de equipos",
        "• Toma de decisiones bajo incertidumbre",
        "• Gestión del cambio y adaptabilidad",
        "",
        "**Acciones Específicas:**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• Lidera iniciativas de transformación organizacional",
            "• Desarrolla a futuros líderes dentro de tu organización",
            "• Busca oportunidades de liderazgo en proyectos complejos",
            "• Comparte tu experiencia a través de mentoring"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• Lidera proyectos multifuncionales",
            "• Desarrolla habilidades de comunicación ejecutiva",
            "• Practica la delegación efectiva",
            "• Busca feedback 360° sobre tu estilo de liderazgo"
        ])
    else:
        recommendations.extend([
            "• Comienza liderando pequeños equipos o proyectos",
            "• Desarrolla habilidades fundamentales de gestión",
            "• Observa y aprende de líderes exitosos",
            "• Toma cursos de desarrollo de liderazgo"
        ])
    
    return recommendations

def generate_teamwork_recommendations(teamwork_scores, overall_score):
    """Genera recomendaciones específicas para Trabajo en Equipo"""
    recommendations = []
    
    recommendations.extend([
        "**Plan de Desarrollo de Trabajo en Equipo**",
        "",
        "**Habilidades Colaborativas a Fortalecer:**",
        "• Comunicación efectiva en grupos",
        "• Resolución colaborativa de problemas",
        "• Apoyo y desarrollo de compañeros",
        "• Gestión constructiva de diferencias",
        "",
        "**Estrategias de Mejora:**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• Facilita dinámicas de equipo y workshops colaborativos",
            "• Mentoriza a nuevos miembros del equipo",
            "• Lidera iniciativas de mejora de cultura colaborativa",
            "• Comparte mejores prácticas de trabajo en equipo"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• Participa activamente en proyectos colaborativos",
            "• Desarrolla habilidades de facilitación grupal",
            "• Practica la escucha activa en reuniones de equipo",
            "• Aprende técnicas de construcción de consenso"
        ])
    else:
        recommendations.extend([
            "• Participa más activamente en actividades grupales",
            "• Practica habilidades básicas de comunicación en grupo",
            "• Observa dinámicas de equipos exitosos",
            "• Busca oportunidades de colaboración en proyectos pequeños"
        ])
    
    return recommendations

def generate_recommendations(dimensional_scores, overall_score, assessment_type=None):
    """Función principal que genera recomendaciones según el tipo de evaluación"""
    
    if not dimensional_scores:
        return ["Se recomienda completar una evaluación completa para obtener recomendaciones personalizadas."]
    
    # Generar recomendaciones específicas según el tipo de evaluación
    if assessment_type == 'Evaluación DISC de Personalidad':
        return generate_disc_recommendations(dimensional_scores, overall_score)
    elif assessment_type == 'Evaluación de Inteligencia Emocional':
        return generate_emotional_intelligence_recommendations(dimensional_scores, overall_score)
    elif assessment_type == 'Evaluación de Asertividad':
        return generate_assertiveness_recommendations(dimensional_scores, overall_score)
    elif assessment_type == 'Evaluación de Habilidades de Liderazgo':
        return generate_leadership_recommendations(dimensional_scores, overall_score)
    elif assessment_type == 'Assessment de Trabajo en Equipo':
        return generate_teamwork_recommendations(dimensional_scores, overall_score)
    else:
        # Fallback a recomendaciones de asertividad para compatibilidad
        return generate_assertiveness_recommendations(dimensional_scores, overall_score)

# Rutas del Frontend
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'success',
        'message': 'Assessment Platform API is running',
        'version': '2.0.0',
        'available_endpoints': ['/coachee-dashboard', '/coach-dashboard', '/admin-dashboard']
    })

@app.route('/favicon.ico')
def favicon():
    return '', 204

# Rutas de autenticación
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/participant-access')
def participant_access():
    return render_template('participant_access.html')

@app.route('/dashboard_selection')
@app.route('/dashboard-selection')
def dashboard_selection():
    return render_template('dashboard_selection.html')



# API Routes principales
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username') or data.get('email')
        password = data.get('password')
        dashboard_type = data.get('dashboard_type', 'auto')  # 'coach', 'coachee', 'auto'
        
        if not username or not password:
            logger.warning(f"Login attempt with missing credentials from {request.remote_addr}")
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        user = User.query.filter((User.username == username) | (User.email == username)).first()  # type: ignore
        
        if user and user.check_password(password) and user.is_active:
            # Verificar compatibilidad de roles si se especifica dashboard_type
            if dashboard_type == 'coach' and user.role != 'coach':
                logger.warning(f"Role mismatch: User {user.username} (role: {user.role}) trying to access coach dashboard")
                return jsonify({'error': 'Este usuario no tiene permisos de coach'}), 403
            elif dashboard_type == 'coachee' and user.role != 'coachee':
                logger.warning(f"Role mismatch: User {user.username} (role: {user.role}) trying to access coachee dashboard")
                return jsonify({'error': 'Este usuario no tiene permisos de coachee'}), 403
                
            # Usar sesiones separadas según el tipo de dashboard
            if user.role == 'coach':
                session['coach_user_id'] = user.id
                # NO limpiar sesión del coachee para permitir sesiones independientes
            elif user.role == 'coachee':
                session['coachee_user_id'] = user.id
                # NO limpiar sesión del coach para permitir sesiones independientes
            
            # NO usar login_user() para evitar conflictos entre sesiones
            session.permanent = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Successful login for user {user.username} (ID: {user.id}, Role: {user.role}, Dashboard: {dashboard_type}) from {request.remote_addr}")
            
            return jsonify({
                'success': True,
                'user': create_user_response(user),
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
    user_info = f"user {current_user.username} (ID: {current_user.id})" if current_user.is_authenticated else "anonymous user"
    logger.info(f"Logout for {user_info}")
    
    logout_user()
    # Limpiar sesiones específicas de dashboards
    session.pop('_user_id', None)
    session.pop('_fresh', None)
    session.pop('temp_coachee_id', None)
    session.pop('coach_user_id', None)
    session.pop('coachee_user_id', None)
    return redirect('/')

@app.route('/api/logout', methods=['POST'])
@either_session_required
def api_logout():
    logger.info(f"API logout for user {current_user.username} (ID: {current_user.id})")
    
    logout_user()
    # Limpiar sesiones específicas de dashboards
    session.pop('_user_id', None)
    session.pop('_fresh', None)
    session.pop('temp_coachee_id', None)
    session.pop('coach_user_id', None)
    session.pop('coachee_user_id', None)
    return jsonify({'success': True, 'message': 'Sesión cerrada exitosamente'}), 200

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar campos requeridos
        required_fields = ['email', 'password', 'full_name']
        if missing_fields := validate_required_fields(data, required_fields):
            return jsonify({'error': f'Campos requeridos: {", ".join(missing_fields)}'}), 400
        
        # Generar username si no se proporciona
        if not data.get('username'):
            email_temp = str(data['email']).strip().lower()
            base_username = re.sub(r'[^a-zA-Z0-9]', '', email_temp.split('@')[0])
            username = base_username.lower()
            
            counter = 1
            original_username = username
            while User.query.filter_by(username=username).first():
                username = f"{original_username}{counter}"
                counter += 1
        else:
            username = str(data['username']).strip()
        
        email = str(data['email']).strip().lower()
        password = str(data['password'])
        full_name = str(data['full_name']).strip()
        
        # Validaciones
        validations = [
            (len(username) < 3, 'El nombre de usuario debe tener al menos 3 caracteres'),
            (len(password) < 6, 'La contraseña debe tener al menos 6 caracteres'),
            (not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email), 'Formato de email inválido'),
            (len(full_name) < 2, 'El nombre completo debe tener al menos 2 caracteres')
        ]
        
        for condition, message in validations:
            if condition:
                return jsonify({'error': message}), 400
        
        # Verificar si el usuario ya existe
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()  # type: ignore
        if existing_user:
            field = 'nombre de usuario' if existing_user.username == username else 'email'
            return jsonify({'error': f'El {field} ya está en uso'}), 409
        
        # Crear nuevo usuario
        role = data.get('role', 'coachee')
        if role not in ['coachee', 'coach', 'platform_admin']:
            role = 'coachee'
            
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role
        )
        
        if data.get('coach_id'):
            if coach := User.query.filter_by(id=data['coach_id'], role='coach').first():
                new_user.coach_id = coach.id
        
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Auto-login
        login_user(new_user, remember=True)
        session.permanent = True
        
        return jsonify({
            'success': True,
            'message': 'Usuario registrado exitosamente',
            'user_id': new_user.id,
            'redirect': get_dashboard_url(new_user.role)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error en registro: {str(e)}'}), 500

# Rutas de administrador
@app.route('/admin-login')
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        admin_user = User.query.filter(User.username == username, User.role == 'platform_admin').first()  # type: ignore
        
        if admin_user and admin_user.check_password(password) and admin_user.is_active:
            login_user(admin_user, remember=True)
            session.permanent = True
            admin_user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'user': create_user_response(admin_user),
                'redirect_url': '/platform-admin-dashboard'
            }), 200
        else:
            return jsonify({'error': 'Credenciales de administrador inválidas'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/admin/change-password', methods=['POST'])
@admin_required
def api_admin_change_password():
    try:
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Contraseña actual y nueva contraseña son requeridas'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'La nueva contraseña debe tener al menos 6 caracteres'}), 400
        
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Contraseña actual incorrecta'}), 401
        
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
    try:
        data = request.get_json()
        
        required_fields = ['username', 'email', 'full_name', 'password']
        if missing_fields := validate_required_fields(data, required_fields):
            return jsonify({'error': f'Campos requeridos: {", ".join(missing_fields)}'}), 400
        
        username, email, full_name, password = data['username'], data['email'], data['full_name'], data['password']
        
        # Validaciones
        if '@' not in email:
            return jsonify({'error': 'Formato de email inválido'}), 400
        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Verificar si el usuario ya existe
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()  # type: ignore
        if existing_user:
            field = 'nombre de usuario' if existing_user.username == username else 'email'
            return jsonify({'error': f'El {field} ya está en uso'}), 409
        
        new_coach = User(
            username=username,
            email=email,
            full_name=full_name,
            role='coach',
            active=True
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
    try:
        coaches = User.query.filter_by(role='coach').order_by(desc(User.created_at)).all()  # type: ignore
        
        coaches_data = []
        for coach in coaches:
            coachees_count = User.query.filter_by(coach_id=coach.id, role='coachee').count()
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
    try:
        # Estadísticas básicas
        total_users = User.query.count()
        total_coaches = User.query.filter_by(role='coach').count()
        total_coachees = User.query.filter_by(role='coachee').count()
        total_admins = User.query.filter_by(role='platform_admin').count()
        total_assessments = AssessmentResult.query.count()
        
        # Puntuación promedio
        avg_score_result = db.session.query(func.avg(AssessmentResult.score)).scalar()
        avg_score = round(avg_score_result, 1) if avg_score_result else 0
        
        # Evaluaciones del último mes
        last_month = datetime.utcnow() - timedelta(days=30)
        recent_assessments = AssessmentResult.query.filter(AssessmentResult.completed_at >= last_month).count()  # type: ignore
        
        # Usuarios activos/inactivos
        active_users = User.query.filter_by(active=True).count()
        inactive_users = User.query.filter_by(active=False).count()
        
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
            'user_distribution': {
                'coaches': total_coaches,
                'coachees': total_coachees,
                'admins': total_admins
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo estadísticas: {str(e)}'}), 500

@app.route('/api/admin/fix-coach-ids', methods=['POST'])
@admin_required
def api_admin_fix_coach_ids():
    """
    Migración para corregir evaluaciones sin coach_id asignado
    """
    try:
        logger.info("🔧 ADMIN: Iniciando migración para corregir coach_ids faltantes")
        
        # Buscar evaluaciones sin coach_id
        evaluations_without_coach = AssessmentResult.query.filter_by(coach_id=None).all()
        logger.info(f"📊 ADMIN: Encontradas {len(evaluations_without_coach)} evaluaciones sin coach_id")
        
        fixed_count = 0
        skipped_count = 0
        errors = []
        
        for evaluation in evaluations_without_coach:
            try:
                # Obtener el usuario que completó la evaluación
                user = User.query.get(evaluation.user_id)
                
                if user and user.coach_id:
                    # El usuario tiene un coach asignado, actualizar la evaluación
                    old_coach_id = evaluation.coach_id
                    evaluation.coach_id = user.coach_id
                    
                    logger.info(f"✅ ADMIN: Corrigiendo evaluación ID {evaluation.id} - Usuario: {user.full_name}, Coach: {user.coach_id}")
                    fixed_count += 1
                else:
                    logger.warning(f"⚠️  ADMIN: Omitida evaluación ID {evaluation.id} - Usuario sin coach o no encontrado")
                    skipped_count += 1
                    
            except Exception as eval_error:
                error_msg = f"Error procesando evaluación ID {evaluation.id}: {str(eval_error)}"
                logger.error(f"❌ ADMIN: {error_msg}")
                errors.append(error_msg)
                skipped_count += 1
        
        if fixed_count > 0:
            try:
                db.session.commit()
                logger.info(f"🎉 ADMIN: Migración completada - {fixed_count} evaluaciones corregidas")
                
                # Verificar resultados
                remaining_null = AssessmentResult.query.filter_by(coach_id=None).count()
                
                return jsonify({
                    'success': True,
                    'message': 'Migración completada exitosamente',
                    'fixed_count': fixed_count,
                    'skipped_count': skipped_count,
                    'remaining_null': remaining_null,
                    'errors': errors
                }), 200
                
            except Exception as commit_error:
                db.session.rollback()
                error_msg = f"Error guardando cambios: {str(commit_error)}"
                logger.error(f"❌ ADMIN: {error_msg}")
                return jsonify({
                    'success': False,
                    'error': error_msg,
                    'fixed_count': 0,
                    'skipped_count': len(evaluations_without_coach)
                }), 500
        else:
            logger.info("ℹ️  ADMIN: No hay evaluaciones que necesiten corrección")
            return jsonify({
                'success': True,
                'message': 'No hay evaluaciones que necesiten corrección',
                'fixed_count': 0,
                'skipped_count': skipped_count,
                'remaining_null': len(evaluations_without_coach),
                'errors': errors
            }), 200
            
    except Exception as e:
        logger.error(f"❌ ADMIN: Error en migración de coach_ids: {str(e)}")
        return jsonify({'error': f'Error en migración: {str(e)}'}), 500

@app.route('/api/admin/check-coach-ids', methods=['GET'])
@admin_required
def api_admin_check_coach_ids():
    """
    Verificar el estado de los coach_ids en las evaluaciones
    """
    try:
        # Contar evaluaciones sin coach_id
        evaluations_without_coach = AssessmentResult.query.filter_by(coach_id=None).count()
        total_evaluations = AssessmentResult.query.count()
        evaluations_with_coach = total_evaluations - evaluations_without_coach
        
        # Obtener detalles de evaluaciones problemáticas
        problematic_evaluations = []
        if evaluations_without_coach > 0:
            problem_evals = AssessmentResult.query.filter_by(coach_id=None).limit(10).all()
            for eval in problem_evals:
                user = User.query.get(eval.user_id)
                assessment = Assessment.query.get(eval.assessment_id)
                problematic_evaluations.append({
                    'evaluation_id': eval.id,
                    'user_name': user.full_name if user else 'Unknown',
                    'user_coach_id': user.coach_id if user else None,
                    'assessment_title': assessment.title if assessment else f'Assessment {eval.assessment_id}',
                    'completed_at': eval.completed_at.isoformat() if eval.completed_at else None
                })
        
        return jsonify({
            'success': True,
            'total_evaluations': total_evaluations,
            'evaluations_with_coach': evaluations_with_coach,
            'evaluations_without_coach': evaluations_without_coach,
            'needs_migration': evaluations_without_coach > 0,
            'percentage_with_coach': round((evaluations_with_coach / total_evaluations * 100), 1) if total_evaluations > 0 else 0,
            'problematic_evaluations': problematic_evaluations
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error verificando coach_ids: {str(e)}'}), 500

# Rutas de coach
@app.route('/coach-login')
def coach_login_page():
    return render_template('coach_login.html')

@app.route('/api/coach/login', methods=['POST'])
def api_coach_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        coach_user = User.query.filter((User.username == username) | (User.email == username), User.role == 'coach').first()  # type: ignore
        
        if coach_user and coach_user.check_password(password) and coach_user.is_active:
            # Usar sesión específica para coach
            session['coach_user_id'] = coach_user.id
            # NO limpiar sesión de coachee para permitir sesiones independientes
            
            # NO usar login_user() para evitar conflictos entre sesiones
            session.permanent = True
            coach_user.last_login = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Successful coach login for {coach_user.username} (ID: {coach_user.id}) from {request.remote_addr}")
            
            return jsonify({
                'success': True,
                'user': create_user_response(coach_user),
                'redirect_url': '/coach-dashboard'
            }), 200
        else:
            logger.warning(f"Failed coach login attempt for username '{username}' from {request.remote_addr}")
            return jsonify({'error': 'Credenciales de coach inválidas'}), 401
            
    except Exception as e:
        logger.error(f"Error in coach login: {str(e)}")
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/coach/profile', methods=['GET'])
@coach_session_required
def api_coach_get_profile():
    try:
        coachees_count = User.query.filter_by(coach_id=current_user.id, role='coachee').count()
        assessments_count = AssessmentResult.query.filter_by(coach_id=current_user.id).count()
        
        return jsonify({
            'success': True,
            'profile': {
                **create_user_response(current_user),
                'coachees_count': coachees_count,
                'assessments_count': assessments_count,
                'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
                'last_login': current_user.last_login.isoformat() if current_user.last_login else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

# Rutas de evaluación
@app.route('/api/questions', methods=['GET'])
def api_get_questions():
    try:
        assessment_id = request.args.get('assessment_id', DEFAULT_ASSESSMENT_ID, type=int)
        
        # Obtener información del assessment
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            return jsonify({'error': f'Assessment con ID {assessment_id} no encontrado'}), 404
        
        questions = Question.query.filter_by(assessment_id=assessment_id, is_active=True).order_by(Question.order).all()
        
        questions_data = [{
            'id': q.id,
            'text': q.text,
            'question_type': q.question_type,
            'order': q.order
        } for q in questions]
        
        return jsonify({
            'success': True,
            'questions': questions_data,
            'assessment_id': assessment_id,
            'assessment_title': assessment.title,
            'assessment_description': assessment.description,
            'scale': {'min': LIKERT_SCALE_MIN, 'max': LIKERT_SCALE_MAX}
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo preguntas: {str(e)}'}), 500

@app.route('/api/save_assessment', methods=['POST'])
def api_save_assessment():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos requeridos'}), 400
        
        responses = data.get('responses', {})
        if not responses:
            return jsonify({'error': 'Respuestas requeridas'}), 400
        
        # Obtener assessment_id de la solicitud o usar default
        assessment_id = data.get('assessment_id', DEFAULT_ASSESSMENT_ID)
        
        # Debug logging
        logger.info(f"🎯 SAVE_ASSESSMENT: Received assessment_id = {assessment_id}")
        logger.info(f"🎯 SAVE_ASSESSMENT: Data keys = {list(data.keys())}")
        logger.info(f"🎯 SAVE_ASSESSMENT: About to check session details")
        
        # Debug de sesión
        logger.info(f"🔍 SAVE_ASSESSMENT: Session keys = {list(session.keys())}")
        logger.info(f"🔍 SAVE_ASSESSMENT: coachee_user_id in session = {session.get('coachee_user_id')}")
        logger.info(f"🔍 SAVE_ASSESSMENT: temp_coachee_id in session = {session.get('temp_coachee_id')}")
        
        # Verificar current_user de forma segura
        try:
            logger.info(f"🔍 SAVE_ASSESSMENT: current_user.is_authenticated = {current_user.is_authenticated}")
            if current_user.is_authenticated:
                logger.info(f"🔍 SAVE_ASSESSMENT: current_user.role = {current_user.role}")
                logger.info(f"🔍 SAVE_ASSESSMENT: current_user.id = {current_user.id}")
        except Exception as e:
            logger.info(f"🔍 SAVE_ASSESSMENT: Cannot access current_user: {e}")
        
        logger.info(f"🎯 SAVE_ASSESSMENT: About to call get_current_coachee()")
        
        # Obtener usuario actual (regular o temporal)
        current_coachee = get_current_coachee()
        logger.info(f"🎯 SAVE_ASSESSMENT: get_current_coachee() returned: {current_coachee}")
        if not current_coachee:
            logger.error(f"❌ SAVE_ASSESSMENT: Usuario no encontrado en sesión")
            return jsonify({'error': 'Usuario no encontrado'}), 401
        
        logger.info(f"✅ SAVE_ASSESSMENT: Found coachee = {current_coachee.username} (ID: {current_coachee.id})")
        
        # Detectar tipo de evaluación y usar función de cálculo apropiada
        # Convertir a entero para asegurar comparación correcta
        assessment_id_int = int(assessment_id) if assessment_id else DEFAULT_ASSESSMENT_ID
        logger.info(f"🎯 SAVE_ASSESSMENT: Converted assessment_id to int = {assessment_id_int}")
        
        if assessment_id_int == 2:  # Evaluación DISC de Personalidad
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_disc_score function")
            score, result_text, dimensional_scores = calculate_disc_score(responses)
        elif assessment_id_int == 3:  # Evaluación de Inteligencia Emocional
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_emotional_intelligence_score function")
            score, result_text, dimensional_scores = calculate_emotional_intelligence_score(responses)
        else:  # Evaluación de Asertividad (ID=1) o cualquier otra
            logger.info(f"🎯 SAVE_ASSESSMENT: Using calculate_assertiveness_score function for assessment_id={assessment_id_int}")
            score, result_text, dimensional_scores = calculate_assertiveness_score(responses)
        
        # Determinar número de respuestas
        num_responses = len(responses) if isinstance(responses, list) else len(responses)
        
        # Crear resultado de evaluación
        assessment_result = AssessmentResult(
            user_id=current_coachee.id,
            assessment_id=assessment_id_int,  # Usar el assessment_id_int correcto
            score=score,
            total_questions=num_responses,
            result_text=result_text,
            dimensional_scores=dimensional_scores
        )
        
        # Si hay coach asignado
        if current_coachee.coach_id:
            assessment_result.coach_id = current_coachee.coach_id
        
        db.session.add(assessment_result)
        db.session.flush()  # Para obtener el ID
        
        # Guardar respuestas individuales
        if isinstance(responses, list):
            # Formato lista: [{'question_id': 1, 'selected_option': 3}, ...]
            for response_data in responses:
                response = Response(
                    user_id=current_coachee.id,
                    question_id=int(response_data['question_id']),
                    selected_option=int(response_data['selected_option']),
                    assessment_result_id=assessment_result.id
                )
                db.session.add(response)
        else:
            # Formato diccionario: {'1': 3, '2': 4, ...}
            for question_id, selected_option in responses.items():
                response = Response(
                    user_id=current_coachee.id,
                    question_id=int(question_id),
                    selected_option=int(selected_option),
                    assessment_result_id=assessment_result.id
                )
                db.session.add(response)
        
        db.session.commit()
        
        logger.info(f"✅ SAVE_ASSESSMENT: Successfully saved assessment result ID {assessment_result.id} for user {current_coachee.username}")
        
        return jsonify({
            'success': True,
            'message': 'Evaluación guardada exitosamente',
            'result': {
                'id': assessment_result.id,
                'score': score,
                'result_text': result_text,
                'completed_at': assessment_result.completed_at.isoformat(),
                'dimensional_scores': dimensional_scores
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ SAVE_ASSESSMENT: Error guardando evaluación: {str(e)}")
        return jsonify({'error': f'Error guardando evaluación: {str(e)}'}), 500

# Rutas de dashboard
@app.route('/coach-dashboard')
def coach_dashboard():
    # Verificar sesión de coach específicamente
    coach_user_id = session.get('coach_user_id')
    
    if not coach_user_id:
        logger.info("No coach session found, redirecting to coach login")
        return redirect(url_for('coach_login_page'))
    
    # Obtener usuario desde la base de datos
    user = User.query.get(coach_user_id)
    if not user or user.role != 'coach':
        logger.warning(f"Invalid coach user or role - User ID: {coach_user_id}")
        session.pop('coach_user_id', None)
        return redirect(url_for('coach_login_page'))
    
    logger.info(f"Coach dashboard access granted - User: {user.username}")
    
    return render_template('coach_dashboard.html')

@app.route('/coachee-dashboard')
def coachee_dashboard():
    # Verificar sesión de coachee específicamente
    coachee_user_id = session.get('coachee_user_id')
    
    if not coachee_user_id:
        logger.info("No coachee session found, redirecting to participant access")
        return redirect(url_for('participant_access'))
    
    # Obtener usuario desde la base de datos
    user = User.query.get(coachee_user_id)
    if not user or user.role != 'coachee':
        logger.warning(f"Invalid coachee user or role - User ID: {coachee_user_id}")
        session.pop('coachee_user_id', None)
        return redirect(url_for('participant_access'))
    
    logger.info(f"Coachee dashboard access granted - User: {user.username}")
    
    return render_template('coachee_dashboard.html')
    return render_template('coachee_dashboard.html')

@app.route('/platform-admin-dashboard')
@login_required
def platform_admin_dashboard():
    if current_user.role != 'platform_admin':
        return redirect(url_for('dashboard_selection'))
    return render_template('admin_dashboard.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    return redirect(url_for('platform_admin_dashboard'))



# Inicialización de la aplicación


# ===== ENDPOINT DE INVITACIÓN FUNCIONAL =====
@app.route('/api/coach/create-invitation-v2', methods=['POST'])
@coach_session_required
def api_coach_create_invitation_v2():
    """Crear una invitación para un nuevo coachee (versión funcional)"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"💌 INVITATION: Request from user {current_coach.username if current_coach else 'Unknown'} ({current_coach.role if current_coach else 'Unknown'})")
        
        # Verificar que es un coach
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"❌ INVITATION: Access denied for user {current_coach.username if current_coach else 'None'} (role: {current_coach.role if current_coach else 'Unknown'})")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden crear invitaciones.'}), 403
            
        data = request.get_json()
        logger.info(f"📝 INVITATION: Received data: {data}")
        
        full_name = data.get('full_name')
        email = data.get('email')
        message = data.get('message', '')
        assigned_assessment_id = data.get('assigned_assessment_id')  # Nueva funcionalidad
        
        if not full_name or not email:
            logger.warning("❌ INVITATION: Missing required fields")
            return jsonify({'error': 'Nombre completo y email son requeridos'}), 400
        
        # Validar formato de email
        if '@' not in email:
            logger.warning(f"❌ INVITATION: Invalid email format: {email}")
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        # Verificar si ya existe un usuario con este email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            logger.warning(f"❌ INVITATION: Email already exists: {email}")
            return jsonify({'error': 'Ya existe un usuario registrado con este email'}), 400
        
        # Generar username único basado en el email
        base_username = email.split('@')[0].lower()
        username = base_username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1
        
        # Generar contraseña segura
        password_chars = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(password_chars) for _ in range(8))
        
        # Crear el usuario coachee
        logger.info(f"👤 INVITATION: Creating coachee {full_name} with username {username}")
        logger.info(f"👤 INVITATION: Coach ID will be set to: {current_coach.id}")
        new_coachee = User(
            username=username,
            email=email,
            full_name=full_name,
            role='coachee',
            coach_id=current_coach.id,
            is_active=True,
            original_password=password  # ✅ Guardar contraseña original para que el coach pueda verla
        )
        new_coachee.set_password(password)
        
        db.session.add(new_coachee)
        db.session.commit()
        
        # Verificar que se creó correctamente
        logger.info(f"✅ INVITATION: Coachee {full_name} created successfully with ID {new_coachee.id}")
        logger.info(f"✅ INVITATION: Verification - Coach ID: {new_coachee.coach_id}, Role: {new_coachee.role}")
        
        # Verificar que se puede encontrar en consulta
        verification_query = User.query.filter_by(coach_id=current_coach.id, role='coachee').all()
        logger.info(f"🔍 INVITATION: Post-creation verification - Found {len(verification_query)} coachees for coach {current_coach.id}")
        for v_coachee in verification_query:
            logger.info(f"🔍 INVITATION: Verification coachee: ID={v_coachee.id}, Name={v_coachee.full_name}, Coach_ID={v_coachee.coach_id}")
        
        # Asignar evaluación si se especificó - Optimizado para Railway
        assessment_assigned = False
        assigned_assessment_title = None
        if assigned_assessment_id:
            try:
                logger.info(f"📋 INVITATION: Attempting to assign assessment ID {assigned_assessment_id} to coachee {new_coachee.id}")
                
                # Verificar que la evaluación existe y está activa - Con verificación robusta
                assessment = None
                try:
                    assessment = Assessment.query.filter_by(id=assigned_assessment_id, is_active=True).first()
                    if assessment:
                        logger.info(f"✅ INVITATION: Assessment found - ID: {assessment.id}, Title: {assessment.title}")
                    else:
                        logger.warning(f"❌ INVITATION: Assessment with ID {assigned_assessment_id} not found or inactive")
                except Exception as query_error:
                    logger.error(f"❌ INVITATION: Database error querying assessment: {query_error}")
                    assessment = None
                
                if assessment:
                    try:
                        # Crear una tarea de evaluación para el coachee con verificaciones Railway
                        new_task = Task(
                            coach_id=current_coach.id,
                            coachee_id=new_coachee.id,
                            title=f"Evaluación: {assessment.title}",
                            description=f"Completa la evaluación '{assessment.title}' asignada por tu coach.",
                            category='evaluation',
                            priority='high',
                            due_date=None,  # Sin fecha límite por defecto
                            is_active=True
                        )
                        
                        db.session.add(new_task)
                        db.session.flush()  # Verificar que se puede crear antes del commit
                        
                        # Verificar que el task se creó correctamente
                        if new_task.id:
                            db.session.commit()
                            assessment_assigned = True
                            assigned_assessment_title = assessment.title
                            logger.info(f"✅ INVITATION: Assessment '{assessment.title}' assigned successfully to coachee {new_coachee.full_name} (Task ID: {new_task.id})")
                        else:
                            logger.error("❌ INVITATION: Task creation failed - no ID generated")
                            db.session.rollback()
                    except Exception as task_error:
                        logger.error(f"❌ INVITATION: Error creating evaluation task: {task_error}")
                        db.session.rollback()
                        # Continuar sin fallar la invitación completa
                else:
                    logger.warning(f"❌ INVITATION: Assessment with ID {assigned_assessment_id} not found or inactive")
            except Exception as e:
                logger.error(f"❌ INVITATION: Error in assessment assignment process: {str(e)}")
                # No fallar la invitación si hay error en la asignación
        
        return jsonify({
            'success': True,
            'message': f'Coachee {full_name} creado exitosamente' + 
                      (f' con evaluación "{assigned_assessment_title}" asignada' if assessment_assigned else ''),
            'coachee': {
                'id': new_coachee.id,
                'username': username,
                'email': email,
                'full_name': full_name,
                'password': password,
                'login_url': f"{request.url_root}login?role=coachee",
                'assigned_assessment': assigned_assessment_title if assessment_assigned else None
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ INVITATION: Error creating coachee: {str(e)}")
        return jsonify({'error': f'Error creando coachee: {str(e)}'}), 500

@app.route('/api/coach/my-coachees', methods=['GET'])
@coach_session_required
def api_coach_my_coachees():
    """Obtener la lista de coachees del coach actual"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"🔍 MY-COACHEES: Request from user {current_coach.username if current_coach else 'Unknown'} (ID: {current_coach.id if current_coach else 'Unknown'}, role: {current_coach.role if current_coach else 'Unknown'})")
        
        # Verificar que es un coach
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"❌ MY-COACHEES: Access denied for user {current_coach.username if current_coach else 'None'} (role: {current_coach.role if current_coach else 'Unknown'})")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver sus coachees.'}), 403
        
        # Obtener coachees del coach actual
        logger.info(f"🔍 MY-COACHEES: Querying coachees for coach_id={current_coach.id}")
        coachees = User.query.filter_by(coach_id=current_coach.id, role='coachee').all()
        logger.info(f"📊 MY-COACHEES: Found {len(coachees)} coachees")
        
        # Log de cada coachee encontrado
        for coachee in coachees:
            logger.info(f"👤 MY-COACHEES: Coachee found - ID: {coachee.id}, Username: {coachee.username}, Email: {coachee.email}, Full Name: {coachee.full_name}, Coach ID: {coachee.coach_id}")
        
        coachees_data = []
        for coachee in coachees:
            # Obtener evaluaciones del coachee ordenadas por fecha
            evaluations = AssessmentResult.query.filter_by(user_id=coachee.id).order_by(desc(AssessmentResult.completed_at)).all()
            
            # Calcular estadísticas de evaluaciones
            last_evaluation_data = None
            avg_score = None
            
            if evaluations:
                last_eval = evaluations[0]  # La más reciente
                last_evaluation_data = {
                    'id': last_eval.id,
                    'score': last_eval.score,
                    'completed_at': last_eval.completed_at.isoformat(),
                    'assessment_id': last_eval.assessment_id
                }
                
                # Calcular promedio de scores
                valid_scores = [e.score for e in evaluations if e.score is not None]
                if valid_scores:
                    avg_score = round(sum(valid_scores) / len(valid_scores), 1)
            
            coachee_data = {
                'id': coachee.id,
                'username': coachee.username,
                'email': coachee.email,
                'full_name': coachee.full_name,
                'name': coachee.full_name,  # ✅ Agregar campo 'name' para compatibilidad
                'created_at': coachee.created_at.isoformat() if coachee.created_at else None,
                'is_active': coachee.is_active,
                'evaluations_count': len(evaluations),
                'last_evaluation': last_evaluation_data,
                'avg_score': avg_score,
                'password': coachee.original_password  # ✅ Incluir contraseña original para que el coach pueda verla
            }
            coachees_data.append(coachee_data)
            logger.info(f"✅ MY-COACHEES: Processed coachee {coachee.full_name} with data: {coachee_data}")
        
        logger.info(f"📤 MY-COACHEES: Returning {len(coachees_data)} coachees in response")
        
        return jsonify({
            'success': True,
            'coachees': coachees_data,
            'total': len(coachees_data)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ MY-COACHEES: Error getting coachees for coach {current_user.username} (ID: {current_user.id}): {str(e)}")
        logger.error(f"❌ MY-COACHEES: Exception details: {e.__class__.__name__}: {str(e)}")
        import traceback
        logger.error(f"❌ MY-COACHEES: Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Error obteniendo coachees: {str(e)}'}), 500

@app.route('/api/coach/debug-users', methods=['GET'])
@coach_session_required
def api_coach_debug_users():
    """Endpoint de debug para verificar usuarios en Railway"""
    try:
        if not current_user.is_authenticated or current_user.role != 'coach':
            return jsonify({'error': 'Access denied'}), 403
            
        logger.info(f"🐛 DEBUG: Coach {current_user.username} (ID: {current_user.id}) requesting user debug info")
        
        # Obtener todos los usuarios
        all_users = User.query.all()
        logger.info(f"🐛 DEBUG: Total users in database: {len(all_users)}")
        
        # Obtener usuarios por rol
        admins = User.query.filter_by(role='platform_admin').all()
        coaches = User.query.filter_by(role='coach').all()
        coachees = User.query.filter_by(role='coachee').all()
        
        # Obtener coachees específicos del coach actual
        my_coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').all()
        
        debug_info = {
            'current_coach': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'role': current_user.role
            },
            'database_stats': {
                'total_users': len(all_users),
                'admins': len(admins),
                'coaches': len(coaches),
                'coachees': len(coachees),
                'my_coachees': len(my_coachees)
            },
            'my_coachees_details': [
                {
                    'id': c.id,
                    'username': c.username,
                    'email': c.email,
                    'full_name': c.full_name,
                    'coach_id': c.coach_id,
                    'is_active': c.is_active,
                    'created_at': c.created_at.isoformat() if c.created_at else None
                } for c in my_coachees
            ],
            'all_coachees_summary': [
                {
                    'id': c.id,
                    'username': c.username,
                    'email': c.email,
                    'coach_id': c.coach_id,
                    'belongs_to_current_coach': c.coach_id == current_user.id
                } for c in coachees
            ]
        }
        
        logger.info(f"🐛 DEBUG: Debug info prepared: {debug_info}")
        return jsonify(debug_info), 200
        
    except Exception as e:
        logger.error(f"❌ DEBUG: Error in debug endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/tasks', methods=['GET'])
@coach_session_required
def api_coach_tasks_get():
    """Obtener tareas del coach"""
    try:
        app.logger.info(f"=== OBTENER TAREAS - Usuario: {current_user.email} ===")
        
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            app.logger.error(f"Acceso denegado - Usuario: {current_user.email}, Role: {current_user.role}")
            return jsonify({'error': 'Acceso denegado.'}), 403
        
        # Obtener todas las tareas asignadas por el coach
        tasks = Task.query.filter_by(coach_id=current_user.id, is_active=True).all()
        app.logger.info(f"Tareas encontradas: {len(tasks)}")
        
        tasks_data = []
        
        for task in tasks:
            # Obtener el último progreso
            latest_progress = TaskProgress.query.filter_by(task_id=task.id).order_by(TaskProgress.created_at.desc()).first()
            
            task_data = {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'category': task.category,
                'priority': task.priority,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'created_at': task.created_at.isoformat(),
                'coachee_name': task.coachee.full_name,  # Nombre directo para compatibilidad frontend
                'coachee': {
                    'id': task.coachee.id,
                    'name': task.coachee.full_name,
                    'email': task.coachee.email
                },
                'status': latest_progress.status if latest_progress else 'pending',
                'progress_percentage': latest_progress.progress_percentage if latest_progress else 0,
                'last_update': latest_progress.created_at.isoformat() if latest_progress else None,
                'completed': latest_progress.status == 'completed' if latest_progress else False
            }
            tasks_data.append(task_data)
        
        app.logger.info(f"Devolviendo {len(tasks_data)} tareas procesadas")
        return jsonify({
            'success': True,
            'tasks': tasks_data
        }), 200
        
    except Exception as e:
        app.logger.error(f"ERROR OBTENIENDO TAREAS: {str(e)}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Error obteniendo tareas: {str(e)}'
        }), 500

@app.route('/api/coach/tasks', methods=['POST'])
@coach_session_required
def api_coach_tasks_post():
    """Crear nueva tarea del coach"""
    try:
        app.logger.info(f"=== INICIO CREACIÓN TAREA - Usuario: {current_user.email} ===")
        
        data = request.get_json()
        app.logger.info(f"Datos recibidos: {data}")
        
        # Validar datos requeridos
        required_fields = ['coachee_id', 'title', 'description', 'category']
        for field in required_fields:
            if not data.get(field):
                app.logger.error(f"Campo faltante: {field}")
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        app.logger.info(f"Validación de campos exitosa")
        
        # Verificar que el coachee pertenece al coach
        coachee = User.query.filter_by(
            id=data['coachee_id'],
            coach_id=current_user.id,
            role='coachee'
        ).first()
        
        if not coachee:
            app.logger.error(f"Coachee no encontrado - ID: {data['coachee_id']}, Coach ID: {current_user.id}")
            return jsonify({'error': 'Coachee no encontrado o no asignado a este coach'}), 404
        
        app.logger.info(f"Coachee encontrado: {coachee.email}")
        
        # Crear la tarea
        due_date = None
        if data.get('due_date'):
            try:
                due_date = datetime.fromisoformat(data['due_date']).date()
            except ValueError:
                app.logger.error(f"Formato de fecha inválido: {data['due_date']}")
                return jsonify({'error': 'Formato de fecha inválido'}), 400
        
        app.logger.info(f"Creando nueva tarea...")
        new_task = Task(
            coach_id=current_user.id,
            coachee_id=data['coachee_id'],
            title=data['title'],
            description=data['description'],
            category=data['category'],
            priority=data.get('priority', 'medium'),
            due_date=due_date
        )
        
        app.logger.info(f"Tarea creada, agregando a sesión...")
        db.session.add(new_task)
        db.session.flush()
        app.logger.info(f"Tarea agregada con ID: {new_task.id}")
        app.logger.info(f"Tarea agregada con ID: {new_task.id}")
        
        # Crear entrada inicial de progreso
        app.logger.info(f"Creando progreso inicial...")
        initial_progress = TaskProgress(
            task_id=new_task.id,
            status='pending',
            progress_percentage=0,
            notes='Tarea creada',
            updated_by=current_user.id
        )
        
        db.session.add(initial_progress)
        app.logger.info(f"Progreso inicial agregado")
        
        app.logger.info(f"Haciendo commit...")
        db.session.commit()
        app.logger.info(f"Commit exitoso")
        
        return jsonify({
            'success': True,
            'message': 'Tarea creada exitosamente',
            'task': {
                'id': new_task.id,
                'title': new_task.title,
                'coachee_name': coachee.full_name
            }
        }), 201
        
    except Exception as e:
        app.logger.error(f"ERROR CREANDO TAREA: {str(e)}")
        app.logger.error(f"Tipo de error: {type(e).__name__}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': f'Error creando tarea: {str(e)}'}), 500

@app.route('/api/coach/tasks/<int:task_id>', methods=['PUT'])
@coach_session_required
def api_coach_update_task(task_id):
    """Actualizar una tarea existente"""
    try:
        app.logger.info(f"=== INICIO ACTUALIZACIÓN TAREA {task_id} - Usuario: {current_user.email} ===")
        
        # Buscar la tarea
        task = Task.query.filter_by(id=task_id, coach_id=current_user.id).first()
        if not task:
            return jsonify({'error': 'Tarea no encontrada.'}), 404
        
        data = request.get_json()
        app.logger.info(f"Datos recibidos para actualización: {data}")
        
        # Validar campos requeridos
        if not data.get('title') or not data.get('title').strip():
            return jsonify({'error': 'El título es obligatorio'}), 400
        
        # Actualizar campos
        task.title = data['title'].strip()
        task.description = data.get('description', '').strip()
        task.category = data.get('category', '')
        
        # Actualizar fecha de vencimiento
        if data.get('due_date'):
            try:
                task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Formato de fecha inválido. Use YYYY-MM-DD'}), 400
        else:
            task.due_date = None
        
        # Actualizar coachee si se proporciona
        if data.get('coachee_id'):
            coachee = User.query.filter_by(id=data['coachee_id'], coach_id=current_user.id, role='coachee').first()
            if not coachee:
                return jsonify({'error': 'Coachee no encontrado o no autorizado.'}), 404
            task.coachee_id = data['coachee_id']
        
        db.session.commit()
        app.logger.info(f"Tarea {task_id} actualizada exitosamente")
        
        return jsonify({
            'success': True,
            'message': 'Tarea actualizada exitosamente',
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'category': task.category,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'coachee_name': task.coachee.full_name if task.coachee else 'No asignado'
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"ERROR ACTUALIZANDO TAREA {task_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Error actualizando tarea: {str(e)}'}), 500

@app.route('/api/coach/tasks/<int:task_id>', methods=['DELETE'])
@coach_session_required
def api_coach_delete_task(task_id):
    """Eliminar una tarea"""
    try:
        app.logger.info(f"=== INICIO ELIMINACIÓN TAREA {task_id} - Usuario: {current_user.email} ===")
        
        # Buscar la tarea
        task = Task.query.filter_by(id=task_id, coach_id=current_user.id).first()
        if not task:
            return jsonify({'error': 'Tarea no encontrada.'}), 404
        
        # Eliminar progreso asociado
        TaskProgress.query.filter_by(task_id=task_id).delete()
        
        # Eliminar la tarea
        db.session.delete(task)
        db.session.commit()
        
        app.logger.info(f"Tarea {task_id} eliminada exitosamente")
        
        return jsonify({
            'success': True,
            'message': 'Tarea eliminada exitosamente'
        }), 200
        
    except Exception as e:
        app.logger.error(f"ERROR ELIMINANDO TAREA {task_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Error eliminando tarea: {str(e)}'}), 500

@app.route('/api/coach/coachee-assessments/<int:coachee_id>', methods=['GET'])
@coach_session_required
def api_coach_coachee_assessments(coachee_id):
    """Obtener todas las evaluaciones disponibles para un coachee específico (espejo del dashboard del coachee)"""
    try:
        logger.info(f"📊 COACHEE-ASSESSMENTS: Request from user {current_user.username} for coachee {coachee_id}")
        
        if not current_user.is_authenticated or current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver evaluaciones de coachees.'}), 403
        
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id, role='coachee').first()
        if not coachee:
            logger.warning(f"❌ COACHEE-ASSESSMENTS: Coachee {coachee_id} not found or unauthorized")
            return jsonify({'error': 'Coachee no encontrado o no autorizado.'}), 404
        
        logger.info(f"🔍 COACHEE-ASSESSMENTS: Getting ALL available assessments for {coachee.full_name} (mirror view)")
        
        # 1. Obtener todas las evaluaciones disponibles (igual que ve el coachee)
        available_assessments = Assessment.query.filter(Assessment.is_active == True).all()
        
        # 2. Obtener tareas de evaluación asignadas a este coachee
        evaluation_tasks = Task.query.filter_by(
            coach_id=current_user.id,
            coachee_id=coachee_id,
            category='evaluation',
            is_active=True
        ).all()
        
        # 3. Obtener evaluaciones completadas por el coachee
        completed_results = AssessmentResult.query.filter_by(user_id=coachee_id).all()
        
        # Crear mapas para facilitar búsquedas
        assigned_tasks_map = {}
        for task in evaluation_tasks:
            # Extraer el título de la evaluación del título de la tarea
            assessment_title = task.title.replace('Evaluación: ', '').strip() if task.title.startswith('Evaluación: ') else task.title.strip()
            assigned_tasks_map[assessment_title] = task
        
        completed_results_map = {}
        for result in completed_results:
            if result.assessment_id not in completed_results_map:
                completed_results_map[result.assessment_id] = []
            completed_results_map[result.assessment_id].append(result)
        
        # 4. Construir la respuesta con todas las evaluaciones (disponibles + estado)
        all_assessments = []
        for assessment in available_assessments:
            # Obtener preguntas para contar total
            questions = Question.query.filter_by(
                assessment_id=assessment.id, 
                is_active=True
            ).count()
            
            # Verificar si está asignada
            is_assigned = assessment.title in assigned_tasks_map
            assigned_task = assigned_tasks_map.get(assessment.title)
            
            # Verificar intentos completados
            completed_attempts = completed_results_map.get(assessment.id, [])
            
            assessment_data = {
                'assessment_id': assessment.id,
                'assessment_title': assessment.title,
                'description': assessment.description,
                'total_questions': questions,
                'is_assigned': is_assigned,
                'task_id': assigned_task.id if assigned_task else None,
                'assigned_date': assigned_task.created_at.isoformat() if assigned_task and assigned_task.created_at else None,
                'due_date': assigned_task.due_date.isoformat() if assigned_task and assigned_task.due_date else None,
                'priority': assigned_task.priority if assigned_task else None,
                'task_description': assigned_task.description if assigned_task else None,
                'completed_attempts': len(completed_attempts),
                'last_attempt': {
                    'id': completed_attempts[-1].id,
                    'score': completed_attempts[-1].score,
                    'completed_at': completed_attempts[-1].completed_at.isoformat(),
                    'result_text': completed_attempts[-1].result_text
                } if completed_attempts else None,
                'created_at': assessment.created_at.isoformat() if assessment.created_at else None
            }
            
            all_assessments.append(assessment_data)
        
        # Estadísticas
        assigned_count = len([a for a in all_assessments if a['is_assigned']])
        completed_count = len([a for a in all_assessments if a['completed_attempts'] > 0])
        
        logger.info(f"📊 COACHEE-ASSESSMENTS: Found {len(all_assessments)} total assessments for {coachee.full_name} ({assigned_count} assigned, {completed_count} completed)")
        
        return jsonify({
            'success': True,
            'coachee': {
                'id': coachee.id,
                'name': coachee.full_name,
                'email': coachee.email
            },
            'assessments': all_assessments,
            'summary': {
                'total_available': len(all_assessments),
                'total_assigned': assigned_count,
                'total_completed': completed_count
            }
        }), 200
        
    except Exception as e:
        logger.error(f"❌ COACHEE-ASSESSMENTS: Error getting assessments for coachee {coachee_id}: {str(e)}")
        import traceback
        logger.error(f"❌ COACHEE-ASSESSMENTS: Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Error obteniendo evaluaciones del coachee: {str(e)}'}), 500

@app.route('/api/coach/unassign-assessment', methods=['POST'])
@coach_session_required
def api_coach_unassign_assessment():
    """Desasignar una evaluación de un coachee eliminando la tarea correspondiente"""
    try:
        logger.info(f"🚫 UNASSIGN-ASSESSMENT: Request from user {current_user.username} (role: {current_user.role})")
        
        if not current_user.is_authenticated or current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden desasignar evaluaciones.'}), 403
        
        data = request.get_json()
        coachee_id = data.get('coachee_id')
        assessment_title = data.get('assessment_title')
        
        if not coachee_id or not assessment_title:
            return jsonify({'error': 'coachee_id y assessment_title son requeridos.'}), 400
        
        logger.info(f"🔍 UNASSIGN-ASSESSMENT: Searching for coachee {coachee_id} and assessment '{assessment_title}'")
        
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id, role='coachee').first()
        if not coachee:
            logger.warning(f"❌ UNASSIGN-ASSESSMENT: Coachee {coachee_id} not found or unauthorized")
            return jsonify({'error': 'Coachee no encontrado o no autorizado.'}), 404
        
        # Buscar la tarea de evaluación específica
        # Probar diferentes variaciones del título
        possible_titles = [
            f"Evaluación: {assessment_title}",
            f"Evaluación: {assessment_title.strip()}",
            assessment_title,
            assessment_title.strip()
        ]
        
        evaluation_task = None
        for title_variant in possible_titles:
            evaluation_task = Task.query.filter_by(
                coach_id=current_user.id,
                coachee_id=coachee_id,
                title=title_variant,
                category='evaluation',
                is_active=True
            ).first()
            if evaluation_task:
                logger.info(f"📋 UNASSIGN-ASSESSMENT: Found task with title variant: '{title_variant}'")
                break
        
        if not evaluation_task:
            logger.warning(f"❌ UNASSIGN-ASSESSMENT: Evaluation task for '{assessment_title}' not found for coachee {coachee.full_name}")
            return jsonify({'error': f'Evaluación "{assessment_title}" no está asignada a este coachee.'}), 404
        
        logger.info(f"📋 UNASSIGN-ASSESSMENT: Found evaluation task ID {evaluation_task.id} for coachee {coachee.full_name}")
        
        # Eliminar progreso asociado a la tarea
        TaskProgress.query.filter_by(task_id=evaluation_task.id).delete()
        logger.info(f"🗑️ UNASSIGN-ASSESSMENT: Deleted task progress for task {evaluation_task.id}")
        
        # Eliminar la tarea de evaluación
        db.session.delete(evaluation_task)
        db.session.commit()
        
        logger.info(f"✅ UNASSIGN-ASSESSMENT: Successfully unassigned '{assessment_title}' from {coachee.full_name}")
        
        return jsonify({
            'success': True,
            'message': f'Evaluación "{assessment_title}" desasignada exitosamente de {coachee.full_name}',
            'coachee': {
                'id': coachee.id,
                'name': coachee.full_name
            },
            'assessment_title': assessment_title
        }), 200
        
    except Exception as e:
        logger.error(f"❌ UNASSIGN-ASSESSMENT: Error unassigning assessment: {str(e)}")
        logger.error(f"❌ UNASSIGN-ASSESSMENT: Exception details: {e.__class__.__name__}: {str(e)}")
        import traceback
        logger.error(f"❌ UNASSIGN-ASSESSMENT: Traceback: {traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': f'Error desasignando evaluación: {str(e)}'}), 500

@app.route('/api/coach/available-assessments', methods=['GET'])
@coach_session_required
def api_coach_available_assessments():
    """Obtener evaluaciones disponibles para asignar a coachees"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        app.logger.info(f"=== OBTENIENDO EVALUACIONES DISPONIBLES - Usuario: {current_coach.email if current_coach else 'Unknown'} ===")
        
        if not current_coach or current_coach.role != 'coach':
            app.logger.warning(f"❌ AVAILABLE-ASSESSMENTS: Access denied for user {current_coach.username if current_coach else 'None'}")
            return jsonify({'error': 'Acceso denegado.'}), 403
        
        app.logger.info("🔍 AVAILABLE-ASSESSMENTS: Querying assessments from database...")
        
        # Verificar que las tablas existen y obtener evaluaciones
        try:
            # Obtener todas las evaluaciones activas
            assessments = Assessment.query.filter_by(is_active=True).all()
            app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: Found {len(assessments)} active assessments")
        except Exception as db_error:
            app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Database query failed: {str(db_error)}")
            # Intentar crear evaluaciones si no existen
            try:
                create_additional_assessments()
                assessments = Assessment.query.filter_by(is_active=True).all()
                app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: After creation attempt, found {len(assessments)} assessments")
            except Exception as create_error:
                app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Could not create assessments: {str(create_error)}")
                assessments = []
        
        assessments_data = []
        for assessment in assessments:
            try:
                # Contar preguntas de la evaluación de manera segura
                questions_count = 0
                try:
                    questions_count = Question.query.filter_by(assessment_id=assessment.id, is_active=True).count()
                except Exception as q_error:
                    app.logger.warning(f"⚠️ AVAILABLE-ASSESSMENTS: Could not count questions for assessment {assessment.id}: {str(q_error)}")
                
                # Contar resultados completados para esta evaluación de manera segura
                completed_count = 0
                try:
                    completed_count = AssessmentResult.query.filter_by(assessment_id=assessment.id).count()
                except Exception as r_error:
                    app.logger.warning(f"⚠️ AVAILABLE-ASSESSMENTS: Could not count results for assessment {assessment.id}: {str(r_error)}")
                
                assessment_data = {
                    'id': assessment.id,
                    'title': assessment.title or 'Sin título',
                    'description': assessment.description or 'Sin descripción',
                    'question_count': questions_count,  # Cambié de questions_count a question_count para consistencia
                    'result_count': completed_count,    # Cambié de completed_count a result_count para consistencia
                    'created_at': assessment.created_at.isoformat() if assessment.created_at else None
                }
                
                assessments_data.append(assessment_data)
                app.logger.info(f"✅ AVAILABLE-ASSESSMENTS: Processed assessment {assessment.id}: {assessment.title}")
                
            except Exception as process_error:
                app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Error processing assessment {assessment.id}: {str(process_error)}")
                # Continuar con las demás evaluaciones
                continue
        
        app.logger.info(f"📤 AVAILABLE-ASSESSMENTS: Returning {len(assessments_data)} evaluations")
        
        # Asegurar que siempre regresemos algo, incluso si está vacío
        return jsonify({
            'success': True,
            'assessments': assessments_data,
            'total': len(assessments_data),
            'message': f'Se encontraron {len(assessments_data)} evaluaciones disponibles'
        }), 200
        
    except Exception as e:
        app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Critical error: {str(e)}")
        import traceback
        app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Traceback: {traceback.format_exc()}")
        
        # Intentar regresar una respuesta mínima de emergencia
        return jsonify({
            'success': False,
            'error': f'Error obteniendo evaluaciones: {str(e)}',
            'assessments': [],
            'total': 0,
            'message': 'Error interno del servidor'
        }), 500

@app.route('/api/admin/create-additional-assessments', methods=['POST'])
@login_required
def api_create_additional_assessments():
    """Crear evaluaciones adicionales (solo administradores)"""
    try:
        # Verificar que es admin
        if not current_user.is_authenticated or current_user.role not in ['platform_admin', 'admin']:
            return jsonify({'error': 'Acceso denegado. Solo administradores.'}), 403
        
        # Crear evaluaciones adicionales
        success = create_additional_assessments()
        
        if success:
            # Contar evaluaciones totales
            total_assessments = Assessment.query.count()
            return jsonify({
                'success': True,
                'message': 'Evaluaciones adicionales creadas exitosamente',
                'total_assessments': total_assessments
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Error al crear evaluaciones adicionales'
            }), 500
            
    except Exception as e:
        app.logger.error(f"ERROR CREANDO EVALUACIONES ADICIONALES: {str(e)}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/admin/check-coach-assignments', methods=['GET'])
@login_required
def api_admin_check_coach_assignments():
    """Verificar evaluaciones sin coach_id asignado"""
    try:
        # Verificar que es admin
        if not current_user.is_authenticated or current_user.role not in ['platform_admin', 'admin']:
            return jsonify({'error': 'Acceso denegado. Solo administradores.'}), 403
        
        # Buscar evaluaciones sin coach_id pero con usuarios que tienen coach
        broken_evaluations = db.session.query(AssessmentResult, User).join(
            User, AssessmentResult.user_id == User.id
        ).filter(
            AssessmentResult.coach_id.is_(None),
            User.coach_id.isnot(None)
        ).all()
        
        broken_data = []
        for result, user in broken_evaluations:
            broken_data.append({
                'evaluation_id': result.id,
                'user_id': user.id,
                'user_name': user.full_name,
                'user_email': user.email,
                'should_have_coach_id': user.coach_id,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None
            })
        
        return jsonify({
            'success': True,
            'broken_evaluations': broken_data,
            'total_broken': len(broken_data),
            'message': f'Encontradas {len(broken_data)} evaluaciones sin coach_id asignado'
        }), 200
        
    except Exception as e:
        app.logger.error(f"ERROR VERIFICANDO ASIGNACIONES: {str(e)}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/admin/fix-coach-assignments', methods=['POST'])
@login_required
def api_admin_fix_coach_assignments():
    """Corregir evaluaciones sin coach_id asignado"""
    try:
        # Verificar que es admin
        if not current_user.is_authenticated or current_user.role not in ['platform_admin', 'admin']:
            return jsonify({'error': 'Acceso denegado. Solo administradores.'}), 403
        
        # Buscar y corregir evaluaciones sin coach_id
        broken_evaluations = db.session.query(AssessmentResult, User).join(
            User, AssessmentResult.user_id == User.id
        ).filter(
            AssessmentResult.coach_id.is_(None),
            User.coach_id.isnot(None)
        ).all()
        
        corrected_count = 0
        corrected_details = []
        
        for result, user in broken_evaluations:
            # Asignar el coach_id correcto
            result.coach_id = user.coach_id
            corrected_count += 1
            
            corrected_details.append({
                'evaluation_id': result.id,
                'user_name': user.full_name,
                'assigned_coach_id': user.coach_id
            })
        
        # Guardar cambios
        db.session.commit()
        
        return jsonify({
            'success': True,
            'corrected_count': corrected_count,
            'corrected_details': corrected_details,
            'message': f'Se corrigieron {corrected_count} evaluaciones'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"ERROR CORRIGIENDO ASIGNACIONES: {str(e)}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

# 🔧 ENDPOINT DEBUG TEMPORAL - Railway Coach Dashboard Issue
@app.route('/api/debug/coach-coachee-problem', methods=['GET'])
def debug_coach_coachee_problem():
    """Endpoint temporal para debuggear problema específico: coachee completa evaluación pero no aparece en dashboard coach"""
    try:
        # Obtener información básica
        total_users = User.query.count()
        total_coaches = User.query.filter_by(role='coach').count()
        total_coachees = User.query.filter_by(role='coachee').count()
        total_evaluations = AssessmentResult.query.count()
        
        # Buscar evaluaciones recientes (últimas 24 horas)
        from datetime import datetime, timedelta
        yesterday = datetime.now() - timedelta(days=1)
        recent_evaluations = AssessmentResult.query.filter(
            AssessmentResult.completed_at >= yesterday
        ).all()
        
        # Analizar cada evaluación reciente
        recent_eval_details = []
        for eval_result in recent_evaluations:
            user = User.query.get(eval_result.user_id)
            coach = User.query.get(user.coach_id) if user and user.coach_id else None
            assessment = Assessment.query.get(eval_result.assessment_id)
            
            recent_eval_details.append({
                'evaluation_id': eval_result.id,
                'user_id': eval_result.user_id,
                'user_name': user.full_name if user else 'Unknown',
                'user_role': user.role if user else 'Unknown',
                'coach_id_in_user': user.coach_id if user else None,
                'coach_name': coach.full_name if coach else 'No Coach',
                'coach_id_in_evaluation': eval_result.coach_id,
                'assessment_title': assessment.title if assessment else 'Unknown',
                'score': eval_result.score,
                'completed_at': eval_result.completed_at.isoformat() if eval_result.completed_at else None,
                'has_coach_id_mismatch': (user.coach_id != eval_result.coach_id) if user else False
            })
        
        # Buscar casos problemáticos específicos
        problematic_cases = []
        coachees_with_evaluations = db.session.query(User).join(
            AssessmentResult, User.id == AssessmentResult.user_id
        ).filter(User.role == 'coachee').distinct().all()
        
        for coachee in coachees_with_evaluations:
            evaluations = AssessmentResult.query.filter_by(user_id=coachee.id).all()
            coach = User.query.get(coachee.coach_id) if coachee.coach_id else None
            
            # Verificar si las evaluaciones aparecerían en dashboard del coach
            evaluations_with_coach_id = [e for e in evaluations if e.coach_id == coachee.coach_id]
            evaluations_without_coach_id = [e for e in evaluations if e.coach_id is None]
            
            if evaluations and coachee.coach_id:
                problematic_cases.append({
                    'coachee_id': coachee.id,
                    'coachee_name': coachee.full_name,
                    'coach_id': coachee.coach_id,
                    'coach_name': coach.full_name if coach else 'Coach not found',
                    'total_evaluations': len(evaluations),
                    'evaluations_with_correct_coach_id': len(evaluations_with_coach_id),
                    'evaluations_with_null_coach_id': len(evaluations_without_coach_id),
                    'latest_evaluation_coach_id': evaluations[-1].coach_id if evaluations else None,
                    'problem_detected': len(evaluations_without_coach_id) > 0
                })
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_users': total_users,
                'total_coaches': total_coaches,
                'total_coachees': total_coachees,
                'total_evaluations': total_evaluations,
                'recent_evaluations_count': len(recent_evaluations)
            },
            'recent_evaluations': recent_eval_details,
            'problematic_cases': problematic_cases,
            'diagnosis': f"Found {len([p for p in problematic_cases if p['problem_detected']])} coachees with evaluation visibility issues"
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Debug error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

# Endpoint temporal público para diagnóstico (REMOVER DESPUÉS) - FORCE DEPLOY
@app.route('/api/public/diagnose-coach-assignments', methods=['GET'])
def api_public_diagnose_coach_assignments():
    """Endpoint temporal público para diagnosticar problemas de coach_id"""
    try:
        # Buscar evaluaciones sin coach_id pero con usuarios que tienen coach
        broken_evaluations = db.session.query(AssessmentResult, User).join(
            User, AssessmentResult.user_id == User.id
        ).filter(
            AssessmentResult.coach_id.is_(None),
            User.coach_id.isnot(None)
        ).all()
        
        broken_data = []
        for result, user in broken_evaluations:
            broken_data.append({
                'evaluation_id': result.id,
                'user_id': user.id,
                'user_name': user.full_name,
                'user_email': user.email,
                'should_have_coach_id': user.coach_id,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None
            })
        
        return jsonify({
            'success': True,
            'broken_evaluations': broken_data,
            'total_broken': len(broken_data),
            'message': f'Encontradas {len(broken_data)} evaluaciones sin coach_id asignado'
        }), 200
        
    except Exception as e:
        app.logger.error(f"ERROR DIAGNÓSTICO PÚBLICO: {str(e)}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/public/fix-coach-assignments/<secret_key>', methods=['POST'])
def api_public_fix_coach_assignments(secret_key):
    """Endpoint temporal público para corregir problemas de coach_id con clave secreta"""
    try:
        # Verificar clave secreta (simple protección)
        if secret_key != 'fix-coach-assignments-2025':
            return jsonify({'error': 'Clave secreta incorrecta'}), 403
        
        # Buscar y corregir evaluaciones sin coach_id
        broken_evaluations = db.session.query(AssessmentResult, User).join(
            User, AssessmentResult.user_id == User.id
        ).filter(
            AssessmentResult.coach_id.is_(None),
            User.coach_id.isnot(None)
        ).all()
        
        corrected_count = 0
        corrected_details = []
        
        for result, user in broken_evaluations:
            # Asignar el coach_id correcto
            result.coach_id = user.coach_id
            corrected_count += 1
            
            corrected_details.append({
                'evaluation_id': result.id,
                'user_name': user.full_name,
                'assigned_coach_id': user.coach_id
            })
        
        # Guardar cambios
        db.session.commit()
        
        return jsonify({
            'success': True,
            'corrected_count': corrected_count,
            'corrected_details': corrected_details,
            'message': f'Se corrigieron {corrected_count} evaluaciones'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"ERROR CORRECCIÓN PÚBLICA: {str(e)}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/coachee-evaluations/<int:coachee_id>', methods=['GET'])
@login_required
def api_coach_coachee_evaluations(coachee_id):
    """Obtener evaluaciones de un coachee específico"""
    try:
        logger.info(f"🔍 COACHEE-EVALUATIONS: Request for coachee_id={coachee_id} from coach {current_user.username} (ID: {current_user.id})")
        
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            logger.warning(f"❌ COACHEE-EVALUATIONS: Access denied - user {current_user.username} not authenticated coach")
            return jsonify({'error': 'Acceso denegado.'}), 403
        
        # Verificar que el coachee pertenece al coach
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id, role='coachee').first()
        if not coachee:
            logger.warning(f"❌ COACHEE-EVALUATIONS: Coachee {coachee_id} not found or not assigned to coach {current_user.id}")
            return jsonify({'error': 'Coachee no encontrado o no autorizado.'}), 404
        
        logger.info(f"✅ COACHEE-EVALUATIONS: Coachee {coachee.full_name} found and authorized")
        
        # Obtener evaluaciones del coachee con información de la evaluación
        evaluations = db.session.query(AssessmentResult, Assessment).join(
            Assessment, AssessmentResult.assessment_id == Assessment.id
        ).filter(AssessmentResult.user_id == coachee_id).all()
        
        logger.info(f"📊 COACHEE-EVALUATIONS: Found {len(evaluations)} total evaluations for coachee {coachee_id}")
        
        evaluations_data = []
        for result, assessment in evaluations:
            eval_data = {
                'id': result.id,
                'assessment_id': result.assessment_id,
                'assessment_title': assessment.title,
                'score': result.score,
                'total_questions': result.total_questions,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'result_text': result.result_text,
                'dimensional_scores': result.dimensional_scores
            }
            evaluations_data.append(eval_data)
            logger.info(f"📋 COACHEE-EVALUATIONS: Evaluation {result.id} - {assessment.title} - Score: {result.score} - Completed: {result.completed_at}")
        
        response_data = {
            'success': True,
            'coachee': {
                'id': coachee.id,
                'full_name': coachee.full_name,
                'email': coachee.email
            },
            'evaluations': evaluations_data,
            'total': len(evaluations_data)
        }
        
        logger.info(f"✅ COACHEE-EVALUATIONS: Returning {len(evaluations_data)} evaluations for coachee {coachee.full_name}")
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo evaluaciones: {str(e)}'}), 500

# ============================================================================
# COACHEE API ENDPOINTS
# ============================================================================

@app.route('/api/coachee/evaluations', methods=['GET'])
@coachee_session_required
def api_coachee_evaluations():
    """Obtener evaluaciones disponibles y completadas para el coachee actual"""
    try:
        current_user = g.current_user
        logger.info(f"🎯 DEBUG: api_coachee_evaluations called by user: {current_user.username}")
        
        # Verificar que es un coachee (ya verificado por el decorador)
        if current_user.role != 'coachee':
            logger.warning(f"❌ DEBUG: Access denied for user: {current_user.username}, role: {current_user.role}")
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        logger.info(f"🔍 DEBUG: Coachee {current_user.username} (ID: {current_user.id}) solicitando evaluaciones")
        logger.info(f"🔍 DEBUG: Coach asignado ID: {current_user.coach_id}")
        
        # Verificar que el coachee tenga un coach asignado
        if not current_user.coach_id:
            logger.info(f"⚠️ DEBUG: Coachee {current_user.username} no tiene coach asignado")
            return jsonify({
                'success': True,
                'available': {},
                'completed': [],
                'total_available': 0,
                'total_completed': 0,
                'message': 'No tienes un coach asignado. Contacta al administrador para obtener acceso a evaluaciones.'
            }), 200
        
        # Si tiene coach asignado, permitir acceso a evaluaciones
        logger.info(f"✅ DEBUG: Coachee {current_user.username} tiene coach asignado (ID: {current_user.coach_id})")
        
        # Obtener evaluaciones completadas
        completed_results = AssessmentResult.query.filter_by(user_id=current_user.id).all()
        logger.info(f"🔍 DEBUG: Evaluaciones completadas encontradas: {len(completed_results)}")
        
        completed_evaluations = []
        for result in completed_results:
            assessment = Assessment.query.get(result.assessment_id)
            completed_evaluations.append({
                'id': result.id,
                'assessment_id': result.assessment_id,
                'assessment_title': assessment.title if assessment else 'Evaluación eliminada',
                'score': result.score,
                'total_questions': result.total_questions,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'result_text': result.result_text,
                'dimensional_scores': result.dimensional_scores,
                'coach_name': current_user.coach.full_name if current_user.coach else 'Sin asignar'
            })
        
        # Obtener solo evaluaciones ASIGNADAS (a través de tareas)
        assigned_tasks = Task.query.filter_by(
            coachee_id=current_user.id,
            is_active=True,
            category='evaluation'
        ).all()
        
        logger.info(f"🔍 DEBUG: Tareas de evaluación asignadas encontradas: {len(assigned_tasks)}")
        
        # Extraer IDs de evaluaciones asignadas del título de las tareas
        assigned_assessment_ids = []
        for task in assigned_tasks:
            # El título de la tarea contiene el nombre de la evaluación
            # Buscar la evaluación que coincida con el título
            for assessment in Assessment.query.filter(Assessment.is_active == True).all():
                if assessment.title in task.title:
                    assigned_assessment_ids.append(assessment.id)
                    logger.info(f"🎯 DEBUG: Found assigned assessment: {assessment.title} (ID: {assessment.id})")
                    break
        
        # Obtener solo las evaluaciones asignadas
        available_assessments = Assessment.query.filter(
            Assessment.id.in_(assigned_assessment_ids),
            Assessment.is_active == True
        ).all() if assigned_assessment_ids else []
        
        logger.info(f"🔍 DEBUG: Evaluaciones asignadas encontradas: {len(available_assessments)}")
        
        available_evaluations = {}
        for assessment in available_assessments:
            questions = Question.query.filter_by(
                assessment_id=assessment.id, 
                is_active=True
            ).order_by(Question.order.asc()).all()
            
            # Verificar si ya ha sido completada anteriormente
            previous_attempts = len([r for r in completed_results if r.assessment_id == assessment.id])
            
            logger.info(f"🔍 DEBUG: Assessment {assessment.id} ({assessment.title}) tiene {len(questions)} preguntas, {previous_attempts} intentos previos")
            
            available_evaluations[str(assessment.id)] = {
                'id': assessment.id,
                'title': assessment.title,
                'description': assessment.description,
                'total_questions': len(questions),
                'previous_attempts': previous_attempts,
                'created_at': assessment.created_at.isoformat() if assessment.created_at else None,
                'coach_name': current_user.coach.full_name if current_user.coach else 'Sin asignar'
            }
        
        logger.info(f"✅ DEBUG: Retornando {len(available_evaluations)} evaluaciones disponibles")
        
        return jsonify({
            'success': True,
            'available': available_evaluations,
            'completed': completed_evaluations,
            'total_available': len(available_evaluations),
            'total_completed': len(completed_evaluations),
            'coach_name': current_user.coach.full_name if current_user.coach else None
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_evaluations: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo evaluaciones: {str(e)}'}), 500

@app.route('/api/coachee/evaluation-history', methods=['GET'])
@coachee_session_required
def api_coachee_evaluation_history():
    """Obtener historial detallado de evaluaciones del coachee"""
    try:
        logger.info(f"🔍 EVALUATION-HISTORY: User {g.current_user.username} (ID: {g.current_user.id}) requesting evaluation history")
        # Obtener todas las evaluaciones completadas con más detalle, ordenadas cronológicamente
        results = AssessmentResult.query.filter_by(user_id=g.current_user.id).order_by(
            AssessmentResult.completed_at.asc()
        ).all()
        
        history = []
        for result in results:
            assessment = Assessment.query.get(result.assessment_id)
            invitation = result.invitation
            
            history.append({
                'id': result.id,
                'assessment': {
                    'id': result.assessment_id,
                    'title': assessment.title if assessment else 'Evaluación eliminada',
                    'description': assessment.description if assessment else None
                },
                'score': result.score,
                'total_score': result.score,  # Para compatibilidad con frontend
                'total_questions': result.total_questions,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'result_text': result.result_text,
                'assertiveness_level': result.result_text,  # Para compatibilidad 
                'result_description': result.result_text,
                'dimensional_scores': result.dimensional_scores,
                'coach': {
                    'id': result.coach.id if result.coach else None,
                    'name': result.coach.full_name if result.coach else 'Sin asignar',
                    'email': result.coach.email if result.coach else None
                },
                'invitation': {
                    'id': invitation.id if invitation else None,
                    'message': invitation.message if invitation else None,
                    'created_at': invitation.created_at.isoformat() if invitation and invitation.created_at else None
                } if invitation else None
            })
        
        # Calcular estadísticas y datos de progreso por tipo de evaluación
        statistics = {}
        progress_data = {}
        
        if history:
            # Agrupar evaluaciones por tipo de assessment
            evaluations_by_type = {}
            for h in history:
                assessment_title = h['assessment']['title']
                if assessment_title not in evaluations_by_type:
                    evaluations_by_type[assessment_title] = []
                evaluations_by_type[assessment_title].append(h)
            
            # Generar datos de progreso para el gráfico
            progress_data = {
                'labels': [],  # Fechas/números de evaluación
                'datasets': []  # Una línea por cada tipo de evaluación
            }
            
            # Crear labels generales basadas en TODAS las evaluaciones cronológicamente
            all_evaluations_chronological = sorted(history, key=lambda x: x['completed_at'])
            progress_data['labels'] = []
            for i, eval_data in enumerate(all_evaluations_chronological, 1):
                if eval_data['completed_at']:
                    date_obj = eval_data['completed_at'].split('T')[0]
                    progress_data['labels'].append(f"#{i} ({date_obj})")
            
            # Crear dataset para cada tipo de evaluación
            type_colors = {
                'Evaluación de Asertividad': '#6282E3',
                'Evaluación DISC de Personalidad': '#A0D8CC',
                'Inteligencia Emocional': '#F4A460',
                'Liderazgo': '#FFB6C1',
                'Trabajo en equipo': '#DDA0DD'
            }
            
            for assessment_type, evaluations in evaluations_by_type.items():
                # Ordenar evaluaciones de este tipo por fecha
                sorted_evaluations = sorted(evaluations, key=lambda x: x['completed_at'])
                
                # Crear datos para este tipo de evaluación
                # Para cada posición en el timeline general, verificar si hay una evaluación de este tipo
                data_points = []
                eval_type_index = 0
                
                for eval_general in all_evaluations_chronological:
                    if eval_general['assessment']['title'] == assessment_type:
                        # Hay una evaluación de este tipo en esta posición
                        if eval_type_index < len(sorted_evaluations):
                            data_points.append(sorted_evaluations[eval_type_index]['score'])
                            eval_type_index += 1
                        else:
                            data_points.append(None)
                    else:
                        # No hay evaluación de este tipo en esta posición
                        data_points.append(None)
                
                # Obtener color para este tipo de evaluación
                color = type_colors.get(assessment_type, '#6B8DA6')  # Color por defecto
                
                dataset = {
                    'label': assessment_type,
                    'data': data_points,
                    'borderColor': color,
                    'backgroundColor': f"{color}20",  # Transparencia
                    'fill': False,
                    'tension': 0.1,
                    'spanGaps': False  # No conectar puntos cuando hay gaps (None)
                }
                progress_data['datasets'].append(dataset)
            
            # Estadísticas generales
            scores = [h['score'] for h in history]
            statistics = {
                'total_evaluations': len(history),
                'average_score': round(sum(scores) / len(scores), 1),
                'latest_score': scores[-1] if scores else None,
                'improvement_trend': 'stable',
                'by_assessment_type': {}
            }
            
            # Estadísticas por tipo de evaluación
            for assessment_type, evaluations in evaluations_by_type.items():
                type_scores = [e['score'] for e in evaluations]
                latest_eval = max(evaluations, key=lambda x: x['completed_at']) if evaluations else None
                
                type_stats = {
                    'count': len(evaluations),
                    'average_score': round(sum(type_scores) / len(type_scores), 1),
                    'latest_score': latest_eval['score'] if latest_eval else None,
                    'latest_date': latest_eval['completed_at'] if latest_eval else None,
                    'improvement_trend': 'stable'
                }
                
                # Calcular tendencia para este tipo
                if len(type_scores) >= 2:
                    if type_scores[-1] > type_scores[-2]:
                        type_stats['improvement_trend'] = 'improving'
                    elif type_scores[-1] < type_scores[-2]:
                        type_stats['improvement_trend'] = 'declining'
                    else:
                        type_stats['improvement_trend'] = 'stable'
                else:
                    type_stats['improvement_trend'] = 'insufficient_data'
                
                statistics['by_assessment_type'][assessment_type] = type_stats
            
            # Calcular tendencia general
            if len(scores) >= 2:
                if scores[-1] > scores[-2]:
                    statistics['improvement_trend'] = 'improving'
                elif scores[-1] < scores[-2]:
                    statistics['improvement_trend'] = 'declining'
                else:
                    statistics['improvement_trend'] = 'stable'
            else:
                statistics['improvement_trend'] = 'insufficient_data'
        
        # Debug logging para revisar los datos
        logger.info(f"🔍 EVALUATION-HISTORY: Returning {len(history)} evaluations")
        logger.info(f"🔍 EVALUATION-HISTORY: Progress data has {len(progress_data.get('datasets', []))} datasets")
        for dataset in progress_data.get('datasets', []):
            logger.info(f"🔍 EVALUATION-HISTORY: Dataset '{dataset.get('label')}' has {len(dataset.get('data', []))} data points: {dataset.get('data', [])[:5]}...")
        logger.info(f"🔍 EVALUATION-HISTORY: Total labels: {len(progress_data.get('labels', []))}")
        
        return jsonify({
            'success': True,
            'history': history,
            'statistics': statistics,
            'progress_data': progress_data,
            'total': len(history)
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_evaluation_history: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo historial: {str(e)}'}), 500

@app.route('/api/coachee/evaluation-details/<int:evaluation_id>', methods=['GET'])
@coachee_session_required
def api_coachee_evaluation_details(evaluation_id):
    """Obtener detalles específicos de una evaluación"""
    try:
        logger.info(f"🔍 EVALUATION-DETAILS: User {g.current_user.username} (ID: {g.current_user.id}) requesting evaluation {evaluation_id}")
        # Obtener la evaluación específica del usuario actual
        result = AssessmentResult.query.filter_by(
            id=evaluation_id, 
            user_id=g.current_user.id
        ).first()
        
        if not result:
            return jsonify({'error': 'Evaluación no encontrada.'}), 404
        
        assessment = Assessment.query.get(result.assessment_id)
        
        # Obtener respuestas individuales
        responses = Response.query.filter_by(
            assessment_result_id=result.id
        ).all()
        
        responses_data = []
        for response in responses:
            question = Question.query.get(response.question_id)
            responses_data.append({
                'question_id': response.question_id,
                'question_text': question.text if question else 'Pregunta eliminada',
                'selected_option': response.selected_option,
                'order': question.order if question else 0
            })
        
        # Ordenar respuestas por orden de pregunta
        responses_data.sort(key=lambda x: x['order'])
        
        # Generar recomendaciones basadas en los resultados
        recommendations = []
        if result.dimensional_scores and result.score is not None:
            recommendations = generate_recommendations(result.dimensional_scores, result.score, assessment.title)
        elif result.score is not None:
            # Si no hay dimensional_scores, generar recomendaciones básicas
            recommendations = generate_recommendations({}, result.score, assessment.title)
        
        return jsonify({
            'success': True,
            'evaluation': {
                'id': result.id,
                'assessment_id': result.assessment_id,
                'assessment_title': assessment.title if assessment else 'Evaluación eliminada',
                'assessment': {
                    'id': result.assessment_id,
                    'title': assessment.title if assessment else 'Evaluación eliminada',
                    'description': assessment.description if assessment else None
                },
                'score': result.score,
                'total_questions': result.total_questions,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'result_text': result.result_text,
                'dimensional_scores': result.dimensional_scores,
                'recommendations': recommendations,
                'responses': responses_data,
                'coach': {
                    'name': result.coach.full_name if result.coach else 'Sin asignar',
                    'email': result.coach.email if result.coach else None
                } if result.coach else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_evaluation_details: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo detalles: {str(e)}'}), 500

@app.route('/api/coach/evaluation-details/<int:evaluation_id>', methods=['GET'])
@login_required
def api_coach_evaluation_details(evaluation_id):
    """Obtener detalles específicos de una evaluación para coaches"""
    try:
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden acceder.'}), 403
        
        # Obtener la evaluación específica
        result = AssessmentResult.query.filter_by(id=evaluation_id).first()
        
        if not result:
            return jsonify({'error': 'Evaluación no encontrada.'}), 404
        
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=result.user_id, coach_id=current_user.id).first()
        
        if not coachee:
            return jsonify({'error': 'Evaluación no autorizada.'}), 403
        
        assessment = Assessment.query.get(result.assessment_id)
        
        # Obtener respuestas individuales
        responses = Response.query.filter_by(
            assessment_result_id=result.id
        ).all()
        
        responses_data = []
        for response in responses:
            question = Question.query.get(response.question_id)
            responses_data.append({
                'question_id': response.question_id,
                'question_text': question.text if question else 'Pregunta eliminada',
                'selected_option': response.selected_option,
                'order': question.order if question else 0
            })
        
        # Ordenar respuestas por orden de pregunta
        responses_data.sort(key=lambda x: x['order'])
        
        # Generar recomendaciones basadas en los resultados (igual que para coachees)
        recommendations = []
        if result.dimensional_scores and result.score is not None:
            recommendations = generate_recommendations(result.dimensional_scores, result.score, assessment.title)
        elif result.score is not None:
            # Si no hay dimensional_scores, generar recomendaciones básicas
            recommendations = generate_recommendations({}, result.score, assessment.title)
        
        # Información del coachee
        coachee = User.query.get(result.user_id)
        
        return jsonify({
            'success': True,
            'evaluation': {
                'id': result.id,
                'assessment': {
                    'id': result.assessment_id,
                    'title': assessment.title if assessment else 'Evaluación eliminada',
                    'description': assessment.description if assessment else None
                },
                'score': result.score,
                'total_questions': result.total_questions,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'result_text': result.result_text,
                'dimensional_scores': result.dimensional_scores,
                'recommendations': recommendations,
                'responses': responses_data,
                'coachee': {
                    'id': coachee.id,
                    'name': coachee.full_name,
                    'email': coachee.email
                } if coachee else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_evaluation_details: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo detalles: {str(e)}'}), 500

@app.route('/api/coachee/profile', methods=['GET'])
@login_required
def api_coachee_profile():
    """Obtener perfil del coachee actual"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        # Obtener información del coach asignado
        coach = None
        if current_user.coach_id:
            coach = User.query.get(current_user.coach_id)
        
        # Obtener estadísticas básicas
        total_evaluations = AssessmentResult.query.filter_by(user_id=current_user.id).count()
        
        return jsonify({
            'success': True,
            'profile': {
                'id': current_user.id,
                'full_name': current_user.full_name,
                'email': current_user.email,
                'role': current_user.role,
                'created_at': current_user.created_at.isoformat() if hasattr(current_user, 'created_at') and current_user.created_at else None,
                'coach': {
                    'id': coach.id if coach else None,
                    'name': coach.full_name if coach else None,
                    'email': coach.email if coach else None
                } if coach else None,
                'stats': {
                    'total_evaluations_completed': total_evaluations
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_profile: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

@app.route('/api/coachee/dashboard-summary', methods=['GET'])
@coachee_session_required
def api_coachee_dashboard_summary():
    """Obtener resumen para el dashboard del coachee"""
    try:
        current_user = g.current_user
        # Verificar que es un coachee (ya verificado por el decorador)
        if current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        # Obtener estadísticas básicas
        total_evaluations = AssessmentResult.query.filter_by(user_id=current_user.id).count()
        
        # Evaluaciones recientes (últimas 5)
        recent_evaluations = AssessmentResult.query.filter_by(user_id=current_user.id)\
            .order_by(AssessmentResult.completed_at.desc()).limit(5).all()
        
        recent_data = []
        latest_evaluation = None
        
        for result in recent_evaluations:
            assessment = Assessment.query.get(result.assessment_id)
            evaluation_data = {
                'id': result.id,
                'assessment_title': assessment.title if assessment else 'Evaluación eliminada',
                'score': result.score,
                'total_score': result.score,  # Para compatibilidad con frontend
                'completed_at': result.completed_at.isoformat() if result.completed_at else None
            }
            recent_data.append(evaluation_data)
            
            # La primera (más reciente) es la última evaluación
            if latest_evaluation is None:
                latest_evaluation = evaluation_data
        
        # Obtener estadísticas de tareas (excluyendo evaluaciones)
        tasks = Task.query.filter(
            Task.coachee_id == current_user.id,
            Task.is_active == True,
            Task.category != 'evaluation'
        ).all()
        pending_tasks = 0
        overdue_tasks = 0
        current_date = date.today()
        
        for task in tasks:
            # Obtener el último progreso
            latest_progress = TaskProgress.query.filter_by(task_id=task.id)\
                .order_by(TaskProgress.created_at.desc()).first()
            
            if latest_progress:
                status = latest_progress.status
                if status in ['pending', 'in_progress']:
                    pending_tasks += 1
                    # Verificar si está vencida
                    if task.due_date:
                        # Convertir due_date a date si es datetime
                        task_due_date = task.due_date.date() if hasattr(task.due_date, 'date') else task.due_date
                        if task_due_date < current_date:
                            overdue_tasks += 1
            else:
                # Sin progreso = pendiente
                pending_tasks += 1
                if task.due_date:
                    # Convertir due_date a date si es datetime
                    task_due_date = task.due_date.date() if hasattr(task.due_date, 'date') else task.due_date
                    if task_due_date < current_date:
                        overdue_tasks += 1
        
        # Obtener coach asignado
        coach = None
        if current_user.coach_id:
            coach = User.query.get(current_user.coach_id)
        
        response_data = {
            'success': True,
            'summary': {
                'coachee': {
                    'name': current_user.full_name,
                    'email': current_user.email,
                    'joined_at': current_user.created_at.isoformat() if current_user.created_at else None
                },
                'coach': {
                    'name': coach.full_name if coach else 'Sin asignar',
                    'email': coach.email if coach else None
                } if coach else None,
                'evaluation_summary': {
                    'total_completed': total_evaluations
                },
                'latest_evaluation': latest_evaluation,
                'tasks_summary': {
                    'pending': pending_tasks,
                    'overdue': overdue_tasks
                },
                'stats': {
                    'total_evaluations': total_evaluations,
                    'recent_evaluations': recent_data
                }
            }
        }
        
        logger.info(f"🔍 DEBUG: Dashboard summary response: {response_data}")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_dashboard_summary: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo resumen: {str(e)}'}), 500

@app.route('/api/coachee/validate-visibility', methods=['GET'])
@login_required
def api_coachee_validate_visibility():
    """Validar que las evaluaciones sean visibles para el coachee actual"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        # Obtener assessment_id específico si se proporciona
        assessment_id = request.args.get('assessment_id', type=int)
        
        # Ejecutar validación
        validation_result = validate_evaluation_visibility(current_user.id, assessment_id)
        
        # Determinar código de respuesta basado en el resultado
        if validation_result['valid']:
            status_code = 200
        else:
            status_code = 400 if 'no encontrado' in validation_result.get('error', '') else 422
        
        return jsonify(validation_result), status_code
        
    except Exception as e:
        logger.error(f"Error en api_coachee_validate_visibility: {str(e)}", exc_info=True)
        return jsonify({
            'valid': False,
            'error': f'Error interno en validación: {str(e)}',
            'details': {'user_id': current_user.id if current_user.is_authenticated else None}
        }), 500

@app.route('/api/admin/validate-coachee-visibility/<int:coachee_id>', methods=['GET'])
@login_required
def api_admin_validate_coachee_visibility(coachee_id):
    """Validar visibilidad de evaluaciones para un coachee específico (solo admin/coach)"""
    try:
        # Verificar permisos (admin o coach del coachee)
        if not current_user.is_authenticated:
            return jsonify({'error': 'Usuario no autenticado'}), 401
        
        if current_user.role == 'admin':
            # Admin puede validar cualquier coachee
            pass
        elif current_user.role == 'coach':
            # Coach solo puede validar sus propios coachees
            coachee = User.query.get(coachee_id)
            if not coachee or coachee.coach_id != current_user.id:
                return jsonify({'error': 'No tienes permisos para validar este coachee'}), 403
        else:
            return jsonify({'error': 'Solo admins y coaches pueden usar esta validación'}), 403
        
        # Obtener assessment_id específico si se proporciona
        assessment_id = request.args.get('assessment_id', type=int)
        
        # Ejecutar validación
        validation_result = validate_evaluation_visibility(coachee_id, assessment_id)
        
        # Agregar información del validador
        validation_result['validated_by'] = {
            'user_id': current_user.id,
            'username': current_user.username,
            'role': current_user.role,
            'validated_at': datetime.utcnow().isoformat()
        }
        
        # Determinar código de respuesta
        if validation_result['valid']:
            status_code = 200
        else:
            status_code = 400 if 'no encontrado' in validation_result.get('error', '') else 422
        
        return jsonify(validation_result), status_code
        
    except Exception as e:
        logger.error(f"Error en api_admin_validate_coachee_visibility: {str(e)}", exc_info=True)
        return jsonify({
            'valid': False,
            'error': f'Error interno en validación: {str(e)}',
            'details': {'coachee_id': coachee_id, 'validator_id': current_user.id if current_user.is_authenticated else None}
        }), 500

@app.route('/api/coachee/tasks', methods=['GET'])
@coachee_session_required
def api_coachee_tasks():
    """Obtener tareas asignadas al coachee (excluyendo evaluaciones)"""
    try:
        current_user = g.current_user
        
        # Obtener tareas asignadas, excluyendo las de categoría 'evaluation'
        # Las evaluaciones se muestran en su propia sección del dashboard
        tasks = Task.query.filter(
            Task.coachee_id == current_user.id,
            Task.is_active == True,
            Task.category != 'evaluation'
        ).order_by(Task.created_at.desc()).all()
        
        tasks_data = []
        for task in tasks:
            # Obtener el último progreso
            latest_progress = TaskProgress.query.filter_by(
                task_id=task.id
            ).order_by(TaskProgress.created_at.desc()).first()
            
            tasks_data.append({
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'category': task.category,
                'priority': task.priority,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'created_at': task.created_at.isoformat(),
                'status': latest_progress.status if latest_progress else 'pending',
                'progress_percentage': latest_progress.progress_percentage if latest_progress else 0,
                'notes': latest_progress.notes if latest_progress else '',
                'coach': {
                    'id': task.coach.id if task.coach else None,
                    'name': task.coach.full_name if task.coach else 'Sin asignar',
                    'email': task.coach.email if task.coach else ''
                },
                'last_update': latest_progress.created_at.isoformat() if latest_progress else task.created_at.isoformat()
            })
        
        return jsonify(tasks_data), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_tasks: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo tareas: {str(e)}'}), 500

@app.route('/api/coachee/tasks/<int:task_id>/progress', methods=['POST', 'PUT'])
@coachee_session_required
def api_coachee_update_task_progress(task_id):
    """Actualizar progreso de tarea desde el lado del coachee"""
    try:
        
        # Verificar que la tarea pertenece al coachee
        task = Task.query.filter_by(
            id=task_id,
            coachee_id=current_user.id
        ).first()
        
        if not task:
            return jsonify({'error': 'Tarea no encontrada'}), 404
        
        data = request.get_json()
        
        # Validar datos
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400
        
        # Crear nueva entrada de progreso
        progress_entry = TaskProgress(
            task_id=task_id,
            status=data.get('status', 'in_progress'),
            progress_percentage=data.get('progress_percentage', 0),
            notes=data.get('notes', ''),
            updated_by=current_user.id
        )
        
        db.session.add(progress_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Progreso actualizado exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coachee_update_task_progress: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error actualizando progreso: {str(e)}'}), 500

@app.route('/api/user/my-profile', methods=['GET'])
@either_session_required
def api_user_my_profile():
    """Obtener perfil del usuario actual (genérico para cualquier rol)"""
    try:
        profile_data = {
            'id': current_user.id,
            'full_name': current_user.full_name,
            'email': current_user.email,
            'role': current_user.role,
            'created_at': current_user.created_at.isoformat() if hasattr(current_user, 'created_at') and current_user.created_at else None
        }
        
        # Agregar información específica según el rol
        if current_user.role == 'coachee':
            coach = None
            if current_user.coach_id:
                coach = User.query.get(current_user.coach_id)
            
            profile_data['coach'] = {
                'id': coach.id if coach else None,
                'name': coach.full_name if coach else None,
                'email': coach.email if coach else None
            } if coach else None
            
            # Estadísticas del coachee
            profile_data['stats'] = {
                'total_evaluations': AssessmentResult.query.filter_by(user_id=current_user.id).count()
            }
            
        elif current_user.role == 'coach':
            # Estadísticas del coach
            coachees_count = User.query.filter_by(coach_id=current_user.id, role='coachee').count()
            total_evaluations = AssessmentResult.query.filter_by(coach_id=current_user.id).count()
            
            profile_data['stats'] = {
                'total_coachees': coachees_count,
                'total_evaluations_supervised': total_evaluations
            }
        
        return jsonify({
            'success': True,
            'profile': profile_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_user_my_profile: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        auto_initialize_database()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5002)), debug=not IS_PRODUCTION)
