#!/usr/bin/env python3
"""
Aplicación Flask para plataforma de evaluación de asertividad
"""
from dotenv import load_dotenv
load_dotenv()

# Imports principales
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
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
    if current_user.is_authenticated and current_user.role == 'coachee':
        return current_user
    
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
        
        logger.info("🎉 AUTO-INIT: Inicialización completa finalizada")
        return True
        
    except Exception as e:
        logger.error(f"❌ AUTO-INIT: Error en inicialización automática: {e}")
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
        total_score = sum(r.get('selected_option', 0) for r in responses)
        num_responses = len(responses)
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
    else:
        # Si es un diccionario (formato anterior)
        total_score = sum(responses.values())
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
                dimension_total += response_dict[str(question_id)]
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

def generate_recommendations(dimensional_scores, overall_score):
    """Genera recomendaciones personalizadas basadas en las puntuaciones dimensionales"""
    
    if not dimensional_scores:
        return ["Se recomienda completar una evaluación completa para obtener recomendaciones personalizadas."]
    
    recommendations = []
    
    # Mapeo de dimensiones a nombres más descriptivos
    dimension_names = {
        'comunicacion': 'Habilidades de Comunicación',
        'derechos': 'Defensa de Derechos Personales',
        'opiniones': 'Expresión de Opiniones',
        'conflictos': 'Manejo de Conflictos',
        'autoconfianza': 'Autoconfianza y Autoestima'
    }
    
    # Identificar las dimensiones más débiles (menos del 60%)
    weak_dimensions = {dim: score for dim, score in dimensional_scores.items() if score < 60}
    
    # Identificar las dimensiones fuertes (80% o más)
    strong_dimensions = {dim: score for dim, score in dimensional_scores.items() if score >= 80}
    
    # Recomendaciones basadas en dimensiones débiles
    dimension_recommendations = {
        'comunicacion': [
            "Practica la escucha activa en tus conversaciones diarias",
            "Utiliza un lenguaje corporal abierto y mantén contacto visual",
            "Expresa tus ideas de manera clara y directa, sin rodeos",
            "Aprende técnicas de comunicación no violenta"
        ],
        'derechos': [
            "Identifica y reconoce tus derechos personales y profesionales",
            "Practica decir 'no' de manera respetuosa pero firme",
            "Establece límites claros en tus relaciones",
            "Desarrolla confianza en tu capacidad para defenderte"
        ],
        'opiniones': [
            "Comparte tus ideas en reuniones y conversaciones grupales",
            "Practica expresar tu punto de vista incluso cuando difiera de otros",
            "Desarrolla argumentos sólidos para respaldar tus opiniones",
            "Acepta que es normal tener perspectivas diferentes"
        ],
        'conflictos': [
            "Aprende técnicas de resolución de conflictos constructiva",
            "Practica mantener la calma durante situaciones tensas",
            "Enfócate en los problemas, no en las personas",
            "Busca soluciones ganar-ganar en los desacuerdos"
        ],
        'autoconfianza': [
            "Reconoce y celebra tus logros y fortalezas",
            "Desafía pensamientos negativos sobre ti mismo",
            "Establece metas pequeñas y alcanzables para construir confianza",
            "Practica la autocompasión y el autocuidado"
        ]
    }
    
    # Agregar recomendaciones para dimensiones débiles
    for dimension, score in weak_dimensions.items():
        dimension_name = dimension_names.get(dimension, dimension)
        dimension_recs = dimension_recommendations.get(dimension, [])
        
        if dimension_recs:
            recommendations.append(f"**{dimension_name}** (Puntuación: {score}%)")
            recommendations.extend(dimension_recs[:2])  # Tomar las 2 primeras recomendaciones
            recommendations.append("")  # Línea en blanco para separación
    
    # Recomendaciones generales basadas en el puntaje general
    if overall_score < 40:
        recommendations.extend([
            "**Recomendaciones Generales:**",
            "Considera trabajar con un coach o terapeuta especializado en asertividad",
            "Lee libros sobre comunicación asertiva y habilidades sociales",
            "Practica técnicas de relajación para manejar la ansiedad social",
            ""
        ])
    elif overall_score < 60:
        recommendations.extend([
            "**Recomendaciones Generales:**",
            "Únete a grupos de práctica de habilidades sociales",
            "Toma cursos de comunicación efectiva",
            "Practica situaciones difíciles con amigos o familiares de confianza",
            ""
        ])
    elif overall_score < 80:
        recommendations.extend([
            "**Recomendaciones Generales:**",
            "Continúa desarrollando las áreas identificadas como oportunidades de mejora",
            "Busca oportunidades para liderar proyectos o equipos",
            "Mentoriza a otros en tus áreas de fortaleza",
            ""
        ])
    else:
        recommendations.extend([
            "**¡Excelente trabajo!**",
            "Mantén tus habilidades asertivas mediante la práctica regular",
            "Considera convertirte en mentor de otros en habilidades de comunicación",
            "Sigue desafiándote en situaciones cada vez más complejas",
            ""
        ])
    
    # Destacar fortalezas
    if strong_dimensions:
        recommendations.append("**Tus Fortalezas:**")
        for dimension, score in strong_dimensions.items():
            dimension_name = dimension_names.get(dimension, dimension)
            recommendations.append(f"• {dimension_name}: {score}% - ¡Excelente desempeño!")
        recommendations.append("")
    
    # Recomendación final
    recommendations.extend([
        "**Recuerda:**",
        "La asertividad es una habilidad que se desarrolla con práctica constante",
        "Sé paciente contigo mismo durante el proceso de mejora",
        "Cada pequeño paso cuenta hacia una comunicación más efectiva"
    ])
    
    return recommendations

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
        
        if not username or not password:
            logger.warning(f"Login attempt with missing credentials from {request.remote_addr}")
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        user = User.query.filter((User.username == username) | (User.email == username)).first()  # type: ignore
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=True)
            session.permanent = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Successful login for user {user.username} (ID: {user.id}, Role: {user.role}) from {request.remote_addr}")
            
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
    session.clear()
    return redirect('/')

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logger.info(f"API logout for user {current_user.username} (ID: {current_user.id})")
    
    logout_user()
    session.clear()
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
            login_user(coach_user, remember=True)
            session.permanent = True
            coach_user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'user': create_user_response(coach_user),
                'redirect_url': '/coach-dashboard'
            }), 200
        else:
            return jsonify({'error': 'Credenciales de coach inválidas'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/coach/profile', methods=['GET'])
@coach_required
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
        
        # Obtener usuario actual (regular o temporal)
        current_coachee = get_current_coachee()
        if not current_coachee:
            return jsonify({'error': 'Usuario no encontrado'}), 401
        
        # Calcular puntuación
        score, result_text, dimensional_scores = calculate_assertiveness_score(responses)
        
        # Determinar número de respuestas
        num_responses = len(responses) if isinstance(responses, list) else len(responses)
        
        # Crear resultado de evaluación
        assessment_result = AssessmentResult(
            user_id=current_coachee.id,
            assessment_id=DEFAULT_ASSESSMENT_ID,
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
        return jsonify({'error': f'Error guardando evaluación: {str(e)}'}), 500

# Rutas de dashboard
@app.route('/coach-dashboard')
@login_required
def coach_dashboard():
    logger.info(f"Coach dashboard access attempt - User: {current_user.username}, Role: {current_user.role}")
    if current_user.role != 'coach':
        logger.warning(f"Access denied to coach dashboard - User: {current_user.username}, Role: {current_user.role}")
        return redirect(url_for('dashboard_selection'))
    logger.info(f"Coach dashboard access granted - User: {current_user.username}")
    return render_template('coach_dashboard.html')

@app.route('/coachee-dashboard')
@login_required
def coachee_dashboard():
    if current_user.role != 'coachee':
        return redirect(url_for('dashboard_selection'))
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
@login_required
def api_coach_create_invitation_v2():
    """Crear una invitación para un nuevo coachee (versión funcional)"""
    try:
        logger.info(f"💌 INVITATION: Request from user {current_user.username} ({current_user.role})")
        
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            logger.warning(f"❌ INVITATION: Access denied for user {current_user.username} (role: {current_user.role})")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden crear invitaciones.'}), 403
            
        data = request.get_json()
        logger.info(f"📝 INVITATION: Received data: {data}")
        
        full_name = data.get('full_name')
        email = data.get('email')
        message = data.get('message', '')
        
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
        logger.info(f"👤 INVITATION: Coach ID will be set to: {current_user.id}")
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
        db.session.commit()
        
        # Verificar que se creó correctamente
        logger.info(f"✅ INVITATION: Coachee {full_name} created successfully with ID {new_coachee.id}")
        logger.info(f"✅ INVITATION: Verification - Coach ID: {new_coachee.coach_id}, Role: {new_coachee.role}")
        
        # Verificar que se puede encontrar en consulta
        verification_query = User.query.filter_by(coach_id=current_user.id, role='coachee').all()
        logger.info(f"🔍 INVITATION: Post-creation verification - Found {len(verification_query)} coachees for coach {current_user.id}")
        for v_coachee in verification_query:
            logger.info(f"🔍 INVITATION: Verification coachee: ID={v_coachee.id}, Name={v_coachee.full_name}, Coach_ID={v_coachee.coach_id}")
        
        return jsonify({
            'success': True,
            'message': f'Coachee {full_name} creado exitosamente',
            'coachee': {
                'id': new_coachee.id,
                'username': username,
                'email': email,
                'full_name': full_name,
                'password': password,
                'login_url': f"{request.url_root}login?role=coachee"
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ INVITATION: Error creating coachee: {str(e)}")
        return jsonify({'error': f'Error creando coachee: {str(e)}'}), 500

@app.route('/api/coach/my-coachees', methods=['GET'])
@login_required
def api_coach_my_coachees():
    """Obtener la lista de coachees del coach actual"""
    try:
        logger.info(f"🔍 MY-COACHEES: Request from user {current_user.username} (ID: {current_user.id}, role: {current_user.role})")
        
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            logger.warning(f"❌ MY-COACHEES: Access denied for user {current_user.username} (role: {current_user.role})")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver sus coachees.'}), 403
        
        # Obtener coachees del coach actual
        logger.info(f"🔍 MY-COACHEES: Querying coachees for coach_id={current_user.id}")
        coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').all()
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
                'avg_score': avg_score
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
@login_required
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
@login_required
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
@login_required
def api_coach_tasks_post():
    """Crear nueva tarea del coach"""
    try:
        app.logger.info(f"=== INICIO CREACIÓN TAREA - Usuario: {current_user.email} ===")
        
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            app.logger.error(f"Acceso denegado - Usuario: {current_user.email}, Role: {current_user.role}")
            return jsonify({'error': 'Acceso denegado.'}), 403
        
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

@app.route('/api/coach/coachee-evaluations/<int:coachee_id>', methods=['GET'])
@login_required
def api_coach_coachee_evaluations(coachee_id):
    """Obtener evaluaciones de un coachee específico"""
    try:
        # Verificar que es un coach
        if not current_user.is_authenticated or current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado.'}), 403
        
        # Verificar que el coachee pertenece al coach
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id, role='coachee').first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no autorizado.'}), 404
        
        # Obtener evaluaciones del coachee
        evaluations = AssessmentResult.query.filter_by(user_id=coachee_id).all()
        
        evaluations_data = []
        for evaluation in evaluations:
            evaluations_data.append({
                'id': evaluation.id,
                'assessment_id': evaluation.assessment_id,
                'score': evaluation.score,
                'total_questions': evaluation.total_questions,
                'completed_at': evaluation.completed_at.isoformat() if evaluation.completed_at else None,
                'result_text': evaluation.result_text,
                'dimensional_scores': evaluation.dimensional_scores
            })
        
        return jsonify({
            'success': True,
            'coachee': {
                'id': coachee.id,
                'full_name': coachee.full_name,
                'email': coachee.email
            },
            'evaluations': evaluations_data,
            'total': len(evaluations_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo evaluaciones: {str(e)}'}), 500

# ============================================================================
# COACHEE API ENDPOINTS
# ============================================================================

@app.route('/api/coachee/evaluations', methods=['GET'])
@login_required
def api_coachee_evaluations():
    """Obtener evaluaciones disponibles y completadas para el coachee actual"""
    try:
        logger.info(f"🎯 DEBUG: api_coachee_evaluations called by user: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
        
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            logger.warning(f"❌ DEBUG: Access denied for user: {current_user.username if current_user.is_authenticated else 'Anonymous'}, role: {current_user.role if current_user.is_authenticated else 'None'}")
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
        
        # Obtener evaluaciones disponibles (TODAS las activas, permiten múltiples intentos)
        available_assessments = Assessment.query.filter(Assessment.is_active == True).all()
        
        logger.info(f"🔍 DEBUG: Evaluaciones activas encontradas: {len(available_assessments)} (disponibles para múltiples intentos)")
        
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
@login_required
def api_coachee_evaluation_history():
    """Obtener historial detallado de evaluaciones del coachee"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        # Obtener todas las evaluaciones completadas con más detalle, ordenadas cronológicamente
        results = AssessmentResult.query.filter_by(user_id=current_user.id).order_by(
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
        
        # Calcular estadísticas
        statistics = {}
        if history:
            scores = [h['score'] for h in history]
            statistics = {
                'total_evaluations': len(history),
                'average_score': round(sum(scores) / len(scores), 1),
                'latest_score': scores[-1] if scores else None,
                'improvement_trend': 'stable'
            }
            
            # Calcular tendencia
            if len(scores) >= 2:
                if scores[-1] > scores[-2]:
                    statistics['improvement_trend'] = 'improving'
                elif scores[-1] < scores[-2]:
                    statistics['improvement_trend'] = 'declining'
                else:
                    statistics['improvement_trend'] = 'stable'
            else:
                statistics['improvement_trend'] = 'insufficient_data'
        
        return jsonify({
            'success': True,
            'history': history,
            'statistics': statistics,
            'total': len(history)
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_evaluation_history: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo historial: {str(e)}'}), 500

@app.route('/api/coachee/evaluation-details/<int:evaluation_id>', methods=['GET'])
@login_required
def api_coachee_evaluation_details(evaluation_id):
    """Obtener detalles específicos de una evaluación"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        # Obtener la evaluación específica del usuario actual
        result = AssessmentResult.query.filter_by(
            id=evaluation_id, 
            user_id=current_user.id
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
            recommendations = generate_recommendations(result.dimensional_scores, result.score)
        elif result.score is not None:
            # Si no hay dimensional_scores, generar recomendaciones básicas
            recommendations = generate_recommendations({}, result.score)
        
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
            recommendations = generate_recommendations(result.dimensional_scores, result.score)
        elif result.score is not None:
            # Si no hay dimensional_scores, generar recomendaciones básicas
            recommendations = generate_recommendations({}, result.score)
        
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
@login_required
def api_coachee_dashboard_summary():
    """Obtener resumen para el dashboard del coachee"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
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
        
        # Obtener estadísticas de tareas
        tasks = Task.query.filter_by(coachee_id=current_user.id, is_active=True).all()
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
@login_required
def api_coachee_tasks():
    """Obtener tareas asignadas al coachee"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
        # Obtener tareas asignadas
        tasks = Task.query.filter_by(
            coachee_id=current_user.id,
            is_active=True
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
@login_required
def api_coachee_update_task_progress(task_id):
    """Actualizar progreso de tarea desde el lado del coachee"""
    try:
        # Verificar que es un coachee
        if not current_user.is_authenticated or current_user.role != 'coachee':
            return jsonify({'error': 'Acceso denegado. Solo coachees pueden acceder.'}), 403
        
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
@login_required
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
