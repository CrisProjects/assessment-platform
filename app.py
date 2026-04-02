#!/usr/bin/env python3
"""
Aplicación Flask para plataforma de evaluación de asertividad
Version: 2026-01-17-23:15 - Fix error 500 en my-coachees
"""
from dotenv import load_dotenv
load_dotenv()

# Imports principales
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g, send_file, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func, desc, inspect, text, and_, or_
from logging.handlers import RotatingFileHandler
import os, secrets, re, logging, string, traceback, json
from urllib.parse import quote as url_quote
import pytz
import boto3
from botocore.exceptions import ClientError
import uuid

# Imports de módulos personalizados
from efectocoach_utils import es_modo_demo, obtener_preguntas_demo, calcular_puntaje_demo
from testpersonal_utils import (
    es_modo_demo_personal, 
    obtener_preguntas_testpersonal, 
    calcular_puntaje_testpersonal,
    obtener_color_area,
    obtener_interpretacion_area
)

# Configuración global
# Configurar zona horaria de Santiago de Chile
SANTIAGO_TZ = pytz.timezone('America/Santiago')
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

# Configurar DATABASE_URI
DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL:
    # Railway/Heroku usan postgres:// pero SQLAlchemy necesita postgresql://
    DATABASE_URI = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    logger.info(f"✅ Using PostgreSQL database (length: {len(DATABASE_URI)} chars)")
else:
    # Local development usa SQLite
    DATABASE_URI = 'sqlite:///assessments.db'
    logger.info("✅ Using local SQLite database")

# Validar que DATABASE_URI no esté vacía
if not DATABASE_URI or DATABASE_URI.strip() == '':
    raise ValueError("DATABASE_URI is empty! Check DATABASE_URL environment variable.")

# Configuración base
config_dict = {
    'SECRET_KEY': SECRET_KEY,
    'SQLALCHEMY_DATABASE_URI': DATABASE_URI,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'PERMANENT_SESSION_LIFETIME': timedelta(hours=24),  # Reducido de 30 días a 24h por seguridad
    'SESSION_PERMANENT': False,  # Cambiar a False para permitir logout completo
    'SESSION_COOKIE_SECURE': IS_PRODUCTION,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'SESSION_REFRESH_EACH_REQUEST': True,  # Actualizar sesión en cada request
    'REMEMBER_COOKIE_DURATION': timedelta(days=7),  # Reducido de 30 a 7 días
    'REMEMBER_COOKIE_SECURE': IS_PRODUCTION,
    'REMEMBER_COOKIE_HTTPONLY': True,
    # Desactivar cache de templates para desarrollo
    'TEMPLATES_AUTO_RELOAD': True,
    'SEND_FILE_MAX_AGE_DEFAULT': 0
}

# Agregar opciones de pool SOLO para PostgreSQL (producción)
if 'postgresql' in DATABASE_URI:
    config_dict['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,  # Verificar conexiones antes de usar
        'pool_recycle': 300,    # Reciclar conexiones cada 5 minutos
        'pool_size': 10,        # Tamaño del pool de conexiones
        'max_overflow': 20,     # Conexiones adicionales permitidas
        'echo': False           # No mostrar SQL queries (excepto en debug)
    }

app.config.update(config_dict)

# Configurar CORS - Restringido solo a dominio de producción
if IS_PRODUCTION:
    # Solo el dominio de producción actual de Railway
    allowed_origins = [os.environ.get('RAILWAY_PUBLIC_DOMAIN', 'https://assessment-platform-production.up.railway.app')]
else:
    # En desarrollo, permitir localhost
    allowed_origins = ['http://localhost:5002', 'http://127.0.0.1:5002', 'http://localhost:3000', 'http://127.0.0.1:3000']

CORS(app, origins=allowed_origins, supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Origin', 'Accept'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Inicialización de extensiones
db = SQLAlchemy(app)

# Habilitar compresión GZIP para reducir tamaño de respuestas (mejora en producción)
Compress(app)
logger.info("✅ Compresión GZIP habilitada")

# Aplicar migraciones automáticas en producción
if IS_PRODUCTION:
    try:
        from auto_migrate import apply_migrations
        logger.info("🔧 Aplicando migraciones automáticas...")
        apply_migrations()
        logger.info("✅ Migraciones completadas")
    except Exception as e:
        logger.warning(f"⚠️ Error en auto-migrations (continuando): {e}")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'dashboard_selection'  # type: ignore
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'info'

# Configurar Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"],  # 🔧 Aumentado para desarrollo
    storage_uri="memory://"
)

# ============================================================================
# FUNCIONES DE VALIDACIÓN Y SANITIZACIÓN DE INPUTS
# ============================================================================

def sanitize_string(input_str, max_length=None):
    """
    Sanitiza strings para prevenir XSS y SQL injection.
    - Elimina caracteres peligrosos y tags HTML
    - Limita longitud si se especifica
    - Convierte a string si no lo es
    """
    if input_str is None:
        return ''
    
    # Convertir a string
    input_str = str(input_str).strip()
    
    # Eliminar tags HTML y caracteres peligrosos
    input_str = re.sub(r'<[^>]*>', '', input_str)
    input_str = re.sub(r'[<>"\';]', '', input_str)
    
    # Limitar longitud
    if max_length and len(input_str) > max_length:
        input_str = input_str[:max_length]
    
    return input_str

def validate_username(username):
    """
    Valida formato de username.
    - Solo alfanuméricos, guiones bajos, puntos y guiones
    - Entre 3 y 80 caracteres
    """
    if not username or not isinstance(username, str):
        return False, 'Username es requerido'
    
    username = username.strip()
    
    if len(username) < 3:
        return False, 'Username debe tener al menos 3 caracteres'
    
    if len(username) > 80:
        return False, 'Username no puede exceder 80 caracteres'
    
    # Solo permitir caracteres seguros: alfanuméricos, guión bajo, punto y guión
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, 'Username solo puede contener letras, números, puntos, guiones y guiones bajos'
    
    return True, sanitize_string(username, 80)

def validate_email(email):
    """
    Valida formato de email.
    - Formato estándar de email
    - Máximo 120 caracteres
    """
    if not email or not isinstance(email, str):
        return False, 'Email es requerido'
    
    email = email.strip().lower()
    
    if len(email) > 120:
        return False, 'Email no puede exceder 120 caracteres'
    
    # Validar formato de email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, 'Formato de email inválido'
    
    return True, sanitize_string(email, 120)

def validate_password(password):
    """
    Valida seguridad de contraseña para login.
    - Mínimo 8 caracteres (mejorado de 6 para mayor seguridad)
    - Máximo 128 caracteres
    """
    if not password or not isinstance(password, str):
        return False, 'Contraseña es requerida'
    
    if len(password) < 8:
        return False, 'Contraseña debe tener al menos 8 caracteres'
    
    if len(password) > 128:
        return False, 'Contraseña no puede exceder 128 caracteres'
    
    return True, password  # No sanitizar contraseñas, solo validar longitud

def validate_full_name(full_name):
    """
    Valida nombre completo.
    - Mínimo 2 caracteres
    - Máximo 200 caracteres
    - Solo letras, espacios y algunos caracteres especiales comunes
    """
    if not full_name or not isinstance(full_name, str):
        return False, 'Nombre completo es requerido'
    
    full_name = full_name.strip()
    
    if len(full_name) < 2:
        return False, 'Nombre completo debe tener al menos 2 caracteres'
    
    if len(full_name) > 200:
        return False, 'Nombre completo no puede exceder 200 caracteres'
    
    # Permitir letras, espacios, acentos y algunos caracteres especiales comunes
    if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s\'-]+$', full_name):
        return False, 'Nombre completo solo puede contener letras, espacios, guiones y apóstrofes'
    
    return True, sanitize_string(full_name, 200)

def validate_and_sanitize_login_input(data):
    """
    Valida y sanitiza inputs de login.
    Retorna: (success: bool, result: dict|str)
    """
    if not data:
        return False, 'Datos requeridos'
    
    # Obtener campos
    username_or_email = data.get('username') or data.get('email')
    password = data.get('password')
    
    if not username_or_email or not password:
        return False, 'Usuario/email y contraseña son requeridos'
    
    # Sanitizar username/email
    username_or_email = sanitize_string(username_or_email, 120)
    
    # Validar contraseña (no sanitizar)
    valid, result = validate_password(password)
    if not valid:
        return False, result
    
    return True, {
        'username_or_email': username_or_email,
        'password': password
    }

def validate_and_sanitize_register_input(data):
    """
    Valida y sanitiza inputs de registro.
    Retorna: (success: bool, result: dict|str)
    """
    if not data:
        return False, 'Datos requeridos'
    
    # Validar email
    email = data.get('email')
    valid, result = validate_email(email)
    if not valid:
        return False, result
    email = result
    
    # Validar contraseña
    password = data.get('password')
    valid, result = validate_password(password)
    if not valid:
        return False, result
    password = result
    
    # Validar nombre completo
    full_name = data.get('full_name')
    valid, result = validate_full_name(full_name)
    if not valid:
        return False, result
    full_name = result
    
    # Validar username (opcional, se genera si no se proporciona)
    username = data.get('username')
    if username:
        valid, result = validate_username(username)
        if not valid:
            return False, result
        username = result
    else:
        # Generar username seguro desde email
        base = re.sub(r'[^a-zA-Z0-9]', '', email.split('@')[0])
        username = sanitize_string(base[:80], 80)
    
    return True, {
        'email': email,
        'password': password,
        'full_name': full_name,
        'username': username
    }

# ============================================================================
# FIN DE FUNCIONES DE VALIDACIÓN
# ============================================================================

# ============================================================================
# FUNCIONES DE AUDITORÍA DE SEGURIDAD
# ============================================================================

def log_security_event(event_type, severity='info', user_id=None, username=None, 
                       user_role=None, description=None, additional_data=None):
    """
    Registra un evento de seguridad en la base de datos.
    
    Args:
        event_type: Tipo de evento ('login_failed', 'unauthorized_access', etc.)
        severity: Nivel de severidad ('info', 'warning', 'error', 'critical')
        user_id: ID del usuario (si existe)
        username: Nombre de usuario (guardado por si el usuario no existe)
        user_role: Rol del usuario
        description: Descripción del evento
        additional_data: Datos adicionales en formato string (puede ser JSON)
    """
    logger.info(f"Security event: {event_type} | {username} | {description}")

def log_failed_login(username, reason='Invalid credentials'):
    """Registra un intento de login fallido con contexto extendido"""
    # Obtener User-Agent para análisis de patrones
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Extraer información básica del User-Agent
    is_mobile = 'Mobile' in user_agent or 'Android' in user_agent or 'iPhone' in user_agent
    device_type = 'mobile' if is_mobile else 'desktop'
    
    log_security_event(
        event_type='login_failed',
        severity='warning',
        username=username,
        description=f'Failed login attempt: {reason} | Device: {device_type} | UA: {user_agent[:100]}'
    )

def log_successful_login(user):
    """Registra un login exitoso"""
    log_security_event(
        event_type='login_success',
        severity='info',
        user_id=user.id,
        username=user.username,
        user_role=user.role,
        description=f'Successful login for {user.role}'
    )

def log_unauthorized_access(user_id=None, username=None, required_role=None):
    """Registra un intento de acceso no autorizado"""
    log_security_event(
        event_type='unauthorized_access',
        severity='error',
        user_id=user_id,
        username=username,
        description=f'Unauthorized access attempt. Required role: {required_role}'
    )

def log_rate_limit_exceeded(username=None):
    """Registra cuando se excede el límite de rate limiting"""
    log_security_event(
        event_type='rate_limit_exceeded',
        severity='warning',
        username=username,
        description='Rate limit exceeded for login attempts'
    )

def log_suspicious_activity(description, user_id=None, username=None, severity='warning'):
    """Registra actividad sospechosa"""
    log_security_event(
        event_type='suspicious_activity',
        severity=severity,
        user_id=user_id,
        username=username,
        description=description
    )

def check_failed_login_threshold(ip_address, time_window_minutes=10, max_attempts=5):
    """
    Verifica si se ha excedido el umbral de intentos fallidos de login desde una IP.
    
    Args:
        ip_address: Dirección IP a verificar
        time_window_minutes: Ventana de tiempo en minutos (default: 10)
        max_attempts: Máximo de intentos permitidos (default: 5)
    
    Returns:
        bool: True si se excedió el umbral, False en caso contrario
    """
    try:
        # Calcular timestamp de inicio de ventana
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        # Contar intentos fallidos desde esta IP en la ventana de tiempo
        failed_attempts = SecurityLog.query.filter(
            SecurityLog.event_type == 'login_failed',
            SecurityLog.ip_address == ip_address,
            SecurityLog.created_at >= time_threshold
        ).count()
        
        return failed_attempts >= max_attempts
        
    except Exception as e:
        logger.error(f"Error checking failed login threshold: {str(e)}")
        return False  # En caso de error, no bloquear el flujo

def check_account_lockout(username, time_window_minutes=15, max_attempts=5):
    """
    Verifica si una cuenta debe ser bloqueada temporalmente por intentos fallidos.
    
    Args:
        username: Nombre de usuario a verificar
        time_window_minutes: Ventana de tiempo en minutos (default: 15)
        max_attempts: Máximo de intentos permitidos (default: 5)
    
    Returns:
        tuple: (is_locked: bool, remaining_time_minutes: int or None, attempts: int)
    """
    try:
        # Calcular timestamp de inicio de ventana
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        # Contar intentos fallidos para este username en la ventana de tiempo
        failed_attempts = SecurityLog.query.filter(
            SecurityLog.event_type == 'login_failed',
            SecurityLog.username == username,
            SecurityLog.created_at >= time_threshold
        ).order_by(SecurityLog.created_at.desc()).all()
        
        attempts_count = len(failed_attempts)
        
        if attempts_count >= max_attempts:
            # Cuenta bloqueada: calcular tiempo restante
            most_recent_attempt = failed_attempts[0].created_at
            lock_expires_at = most_recent_attempt + timedelta(minutes=time_window_minutes)
            remaining_time = (lock_expires_at - datetime.utcnow()).total_seconds() / 60
            
            if remaining_time > 0:
                return (True, int(remaining_time) + 1, attempts_count)
        
        return (False, None, attempts_count)
        
    except Exception as e:
        logger.error(f"Error checking account lockout: {str(e)}")
        return (False, None, 0)  # En caso de error, no bloquear

def send_community_invitation(invitation, community, inviter, method='email'):
    """
    Envía invitación a comunidad por email, WhatsApp o SMS.
    
    Args:
        invitation: Objeto CommunityInvitation
        community: Objeto CoachCommunity
        inviter: Usuario que envía la invitación
        method: 'email', 'whatsapp' o 'sms'
    
    Returns:
        dict: {'success': bool, 'message': str, 'whatsapp_link': str (opcional)}
    """
    try:
        invitation_link = f"{request.host_url}coach-login?invitation={invitation.token}"
        inviter_name = inviter.full_name or inviter.email
        
        message_text = f"""
¡Hola {invitation.invitee_name}!

{inviter_name} te ha invitado a unirte a la comunidad "{community.name}" en InstaCoach Assessment Platform.

{invitation.message if invitation.message else ''}

Para aceptar la invitación, haz clic en el siguiente enlace:
{invitation_link}

Esta invitación expira en 7 días.

Saludos,
Equipo InstaCoach
        """.strip()
        
        if method == 'email':
            # Enviar por email
            smtp_server = os.environ.get('SMTP_SERVER')
            smtp_port = int(os.environ.get('SMTP_PORT', '587'))
            smtp_username = os.environ.get('SMTP_USERNAME')
            smtp_password = os.environ.get('SMTP_PASSWORD')
            
            if not all([smtp_server, smtp_username, smtp_password]):
                logger.warning("SMTP not configured, returning invitation link only")
                return {
                    'success': True,
                    'message': 'Invitación creada (email no configurado)',
                    'invitation_link': invitation_link
                }
            
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg['From'] = smtp_username
            msg['To'] = invitation.invitee_email
            msg['Subject'] = f'Invitación a {community.name} - InstaCoach'
            
            # HTML body
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #f9f9f9;">
                    <h2 style="color: #6366f1;">¡Has sido invitado!</h2>
                    <p>Hola <strong>{invitation.invitee_name}</strong>,</p>
                    <p><strong>{inviter_name}</strong> te ha invitado a unirte a la comunidad <strong>"{community.name}"</strong> en InstaCoach Assessment Platform.</p>
                    {f'<p style="background: #f0f0f0; padding: 15px; border-left: 4px solid #6366f1; margin: 20px 0;"><em>{invitation.message}</em></p>' if invitation.message else ''}
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{invitation_link}" 
                           style="background: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
                            Aceptar Invitación
                        </a>
                    </div>
                    <p style="color: #666; font-size: 0.9em;">Esta invitación expira en 7 días.</p>
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    <p style="color: #999; font-size: 0.85em;">Equipo InstaCoach Assessment Platform</p>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            msg.attach(MIMEText(message_text, 'plain'))
            
            # Enviar email
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"📧 Email de invitación enviado a {invitation.invitee_email}")
            return {
                'success': True,
                'message': 'Invitación enviada por email',
                'invitation_link': invitation_link
            }
            
        elif method == 'whatsapp':
            # Generar link de WhatsApp
            phone = invitation.invitee_phone.replace(' ', '').replace('-', '').replace('+', '')
            whatsapp_message = f"""¡Hola {invitation.invitee_name}!

{inviter_name} te ha invitado a unirte a la comunidad "{community.name}" en InstaCoach.

{invitation.message if invitation.message else ''}

Acepta la invitación aquí: {invitation_link}

Expira en 7 días."""
            
            whatsapp_link = f"https://wa.me/{phone}?text={url_quote(whatsapp_message)}"
            
            logger.info(f"📱 Link de WhatsApp generado para {invitation.invitee_phone}")
            return {
                'success': True,
                'message': 'Link de WhatsApp generado',
                'whatsapp_link': whatsapp_link,
                'invitation_link': invitation_link
            }
            
        elif method == 'sms':
            # Por ahora, SMS solo retorna el mensaje a enviar
            # En producción, integrar con Twilio, AWS SNS, etc.
            sms_text = f"InstaCoach: {inviter_name} te invitó a '{community.name}'. Acepta aquí: {invitation_link} (expira en 7 días)"
            
            logger.info(f"📲 SMS preparado para {invitation.invitee_phone}")
            return {
                'success': True,
                'message': 'SMS preparado (integración pendiente)',
                'sms_text': sms_text,
                'invitation_link': invitation_link,
                'note': 'Integra con Twilio o AWS SNS para envío automático'
            }
        
    except Exception as e:
        logger.error(f"Error enviando invitación por {method}: {str(e)}", exc_info=True)
        return {
            'success': False,
            'message': f'Error enviando por {method}: {str(e)}',
            'invitation_link': invitation_link  # Siempre retornar el link
        }


def send_coach_request_email(coach_request):
    """
    Envía email a support@instacoach.cl cuando se recibe una nueva solicitud de coach.
    
    Args:
        coach_request: Instancia de CoachRequest con la información del solicitante
    """
    try:
        # Obtener configuración SMTP
        smtp_server = os.environ.get('SMTP_SERVER')
        smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        support_email = 'support@instacoach.cl'
        
        if not all([smtp_server, smtp_username, smtp_password]):
            logger.warning("⚠️ SMTP not configured - Coach request email not sent")
            return False
        
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import json
        
        # Parsear áreas de expertise
        areas_list = []
        if coach_request.areas:
            try:
                areas_list = json.loads(coach_request.areas) if isinstance(coach_request.areas, str) else coach_request.areas
            except:
                areas_list = []
        
        areas_text = ', '.join(areas_list) if areas_list else 'No especificado'
        
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = support_email
        msg['Subject'] = f'Nueva Solicitud de Coach - {coach_request.full_name}'
        
        # HTML body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 700px; margin: 0 auto; padding: 20px; background: #f9f9f9;">
                <h2 style="color: #6366f1; border-bottom: 3px solid #6366f1; padding-bottom: 10px;">
                    📝 Nueva Solicitud de Coach
                </h2>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #333; margin-top: 0;">Información Personal</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; width: 150px;">Nombre:</td>
                            <td style="padding: 8px 0;">{coach_request.full_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Email:</td>
                            <td style="padding: 8px 0;">{coach_request.email}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Usuario:</td>
                            <td style="padding: 8px 0;">{coach_request.username}</td>
                        </tr>
                    </table>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #333; margin-top: 0;">Información Profesional</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; width: 150px;">Áreas de Expertise:</td>
                            <td style="padding: 8px 0;">{areas_text}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Experiencia:</td>
                            <td style="padding: 8px 0;">{coach_request.experiencia or 'No especificado'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Estilo de Coaching:</td>
                            <td style="padding: 8px 0;">{coach_request.estilo or 'No especificado'}</td>
                        </tr>
                    </table>
                </div>
                
                {f'''<div style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #6366f1;">
                    <h3 style="color: #333; margin-top: 0;">Biografía</h3>
                    <p style="margin: 0; white-space: pre-wrap;">{coach_request.bio}</p>
                </div>''' if coach_request.bio else ''}
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
                    <p style="margin: 0;">
                        <strong>⏰ Fecha de solicitud:</strong> {coach_request.created_at.strftime('%d/%m/%Y %H:%M')}
                    </p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <p style="color: #666;">Para aprobar esta solicitud, inicia sesión en el panel de administración:</p>
                    <a href="http://localhost:5002/admin/dashboard-alpine" 
                       style="background: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold; margin: 10px 5px;">
                        Ir al Panel de Admin
                    </a>
                </div>
                
                <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                <p style="color: #999; font-size: 0.85em; text-align: center;">
                    Sistema InstaCoach Assessment Platform<br>
                    Este es un email automático, por favor no responder.
                </p>
            </div>
        </body>
        </html>
        """
        
        # Plain text version - preparar sección de biografía
        bio_section = f"BIOGRAFÍA\n{'-' * 50}\n{coach_request.bio}\n" if coach_request.bio else ""
        
        text_body = f"""
Nueva Solicitud de Coach - InstaCoach

INFORMACIÓN PERSONAL
--------------------
Nombre: {coach_request.full_name}
Email: {coach_request.email}
Usuario: {coach_request.username}

INFORMACIÓN PROFESIONAL
-----------------------
Áreas de Expertise: {areas_text}
Experiencia: {coach_request.experiencia or 'No especificado'}
Estilo de Coaching: {coach_request.estilo or 'No especificado'}

{bio_section}

Fecha de solicitud: {coach_request.created_at.strftime('%d/%m/%Y %H:%M')}

Para revisar y aprobar esta solicitud, accede al panel de administración:
http://localhost:5002/admin/dashboard-alpine

---
Sistema InstaCoach Assessment Platform
        """.strip()
        
        msg.attach(MIMEText(html_body, 'html'))
        msg.attach(MIMEText(text_body, 'plain'))
        
        # Enviar email
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"📧 Email de solicitud de coach enviado a {support_email} para {coach_request.full_name}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error enviando email de solicitud de coach: {str(e)}", exc_info=True)
        return False


def send_welcome_email_to_new_coach(coach, password, admin_name):
    """
    Envía email de bienvenida a un nuevo coach creado por el admin.
    
    Args:
        coach: Instancia de User con role='coach'
        password: Contraseña en texto plano para incluir en el email
        admin_name: Nombre del administrador que creó la cuenta
    
    Returns:
        dict con resultado del envío
    """
    try:
        smtp_server = os.environ.get('SMTP_SERVER')
        smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        support_email = 'support@instacoach.cl'
        
        if not all([smtp_server, smtp_username, smtp_password]):
            logger.warning("⚠️ SMTP not configured - Welcome email not sent")
            return {'success': False, 'message': 'SMTP no configurado'}
        
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['From'] = support_email
        msg['To'] = coach.email
        msg['Subject'] = '🎉 Bienvenido a InstaCoach - Credenciales de Acceso'
        
        dashboard_url = f"{request.host_url}coach-dashboard"
        login_url = f"{request.host_url}coach-login"
        
        # HTML body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #f9f9f9;">
                <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 40px; border-radius: 12px 12px 0 0; text-align: center;">
                    <h1 style="margin: 0; font-size: 32px;">🎉 ¡Bienvenido a InstaCoach!</h1>
                    <p style="margin: 15px 0 0 0; font-size: 18px; opacity: 0.95;">Tu cuenta de Coach ha sido creada exitosamente</p>
                </div>
                
                <div style="background: white; padding: 35px; border-radius: 0 0 12px 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <p style="font-size: 16px; margin-top: 0;">Hola <strong>{coach.full_name}</strong>,</p>
                    
                    <p>Tu cuenta de coach ha sido creada por {admin_name}. Ahora puedes acceder a la plataforma InstaCoach Assessment Platform y comenzar a trabajar con tus coachees.</p>
                    
                    <div style="background: #f0f4ff; padding: 25px; border-radius: 10px; margin: 25px 0; border-left: 5px solid #6366f1;">
                        <h3 style="color: #6366f1; margin-top: 0; display: flex; align-items: center;">
                            🔑 Tus credenciales de acceso
                        </h3>
                        <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                            <tr>
                                <td style="padding: 10px 0; font-weight: bold; color: #555; width: 140px;">Usuario:</td>
                                <td style="padding: 10px 0; font-family: 'Courier New', monospace; background: white; padding: 8px 12px; border-radius: 6px;"><strong>{coach.username}</strong></td>
                            </tr>
                            <tr>
                                <td style="padding: 10px 0; font-weight: bold; color: #555;">Email:</td>
                                <td style="padding: 10px 0; font-family: 'Courier New', monospace; background: white; padding: 8px 12px; border-radius: 6px;">{coach.email}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px 0; font-weight: bold; color: #555;">Contraseña:</td>
                                <td style="padding: 10px 0; font-family: 'Courier New', monospace; background: #fff3cd; padding: 8px 12px; border-radius: 6px; color: #856404;"><strong>{password}</strong></td>
                            </tr>
                        </table>
                        <p style="margin: 15px 0 0 0; font-size: 13px; color: #856404; background: #fff3cd; padding: 12px; border-radius: 6px;">
                            ⚠️ <strong>Importante:</strong> Por seguridad, te recomendamos cambiar tu contraseña después del primer inicio de sesión.
                        </p>
                    </div>
                    
                    <div style="text-align: center; margin: 35px 0;">
                        <a href="{login_url}" 
                           style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 16px 40px; text-decoration: none; border-radius: 10px; display: inline-block; font-weight: bold; font-size: 16px; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);">
                            Iniciar Sesión Ahora →
                        </a>
                    </div>
                    
                    <div style="background: #e8f5e9; padding: 20px; border-radius: 10px; margin: 25px 0; border-left: 5px solid #4caf50;">
                        <h3 style="color: #2e7d32; margin-top: 0;">✨ ¿Qué puedes hacer en InstaCoach?</h3>
                        <ul style="color: #555; line-height: 1.8; margin: 10px 0; padding-left: 20px;">
                            <li>Gestionar tus coachees y su progreso</li>
                            <li>Asignar y revisar evaluaciones personalizadas</li>
                            <li>Programar sesiones de coaching</li>
                            <li>Compartir contenido y recursos</li>
                            <li>Crear planes de desarrollo personalizados</li>
                            <li>Unirte a comunidades de coaches</li>
                        </ul>
                    </div>
                    
                    <div style="background: #fff3e0; padding: 20px; border-radius: 10px; margin: 25px 0; border-left: 5px solid #ff9800;">
                        <h3 style="color: #e65100; margin-top: 0;">📞 ¿Necesitas ayuda?</h3>
                        <p style="margin: 5px 0; color: #555;">Si tienes alguna pregunta o necesitas asistencia, no dudes en contactarnos:</p>
                        <p style="margin: 10px 0;"><strong>📧 Email:</strong> <a href="mailto:{support_email}" style="color: #6366f1; text-decoration: none;">{support_email}</a></p>
                    </div>
                    
                    <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
                    
                    <p style="color: #999; font-size: 13px; text-align: center; margin: 0;">
                        <strong>Equipo InstaCoach</strong><br>
                        Este email fue enviado automáticamente. Por favor no responder directamente.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version
        text_body = f"""
¡Bienvenido a InstaCoach!

Hola {coach.full_name},

Tu cuenta de coach ha sido creada por {admin_name}. Ahora puedes acceder a la plataforma InstaCoach Assessment Platform.

CREDENCIALES DE ACCESO
-----------------------
Usuario: {coach.username}
Email: {coach.email}
Contraseña: {password}

⚠️ IMPORTANTE: Por seguridad, te recomendamos cambiar tu contraseña después del primer inicio de sesión.

Inicia sesión aquí: {login_url}

¿QUÉ PUEDES HACER EN INSTACOACH?
- Gestionar tus coachees y su progreso
- Asignar y revisar evaluaciones personalizadas
- Programar sesiones de coaching
- Compartir contenido y recursos
- Crear planes de desarrollo personalizados
- Unirte a comunidades de coaches

¿NECESITAS AYUDA?
Si tienes alguna pregunta o necesitas asistencia, contáctanos:
Email: {support_email}

---
Equipo InstaCoach
        """.strip()
        
        msg.attach(MIMEText(html_body, 'html'))
        msg.attach(MIMEText(text_body, 'plain'))
        
        # Enviar email
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"📧 Email de bienvenida enviado a {coach.email}")
        return {'success': True, 'message': 'Email enviado exitosamente', 'method': 'email'}
        
    except Exception as e:
        logger.error(f"❌ Error enviando email de bienvenida: {str(e)}", exc_info=True)
        return {'success': False, 'message': f'Error: {str(e)}', 'method': 'email'}


def generate_whatsapp_welcome_message(coach, password, admin_name):
    """
    Genera mensaje de bienvenida para WhatsApp.
    
    Args:
        coach: Instancia de User con role='coach'
        password: Contraseña en texto plano
        admin_name: Nombre del administrador
    
    Returns:
        dict con el mensaje y link de WhatsApp
    """
    try:
        from urllib.parse import quote as url_quote
        
        login_url = f"{request.host_url}coach-login"
        
        message = f"""🎉 *¡Bienvenido a InstaCoach!*

Hola *{coach.full_name}*,

Tu cuenta de coach ha sido creada por {admin_name}.

🔑 *Credenciales de Acceso:*
👤 Usuario: {coach.username}
📧 Email: {coach.email}
🔒 Contraseña: {password}

⚠️ *Importante:* Cambia tu contraseña después del primer inicio de sesión.

Inicia sesión aquí: {login_url}

✨ *En InstaCoach puedes:*
• Gestionar tus coachees
• Asignar evaluaciones
• Programar sesiones
• Compartir contenido
• Crear planes de desarrollo

📞 ¿Necesitas ayuda?
Contáctanos: support@instacoach.cl

---
Equipo InstaCoach"""
        
        logger.info(f"📱 Mensaje de WhatsApp generado para {coach.full_name}")
        return {
            'success': True,
            'message': 'Mensaje generado exitosamente',
            'whatsapp_text': message,
            'whatsapp_message': message,
            'method': 'whatsapp',
            'note': 'Copia este mensaje y envíalo por WhatsApp'
        }
        
    except Exception as e:
        logger.error(f"❌ Error generando mensaje WhatsApp: {str(e)}", exc_info=True)
        return {'success': False, 'message': f'Error: {str(e)}', 'method': 'whatsapp'}


def send_confirmation_email_to_applicant(coach_request):
    """
    Envía email de confirmación al solicitante confirmando que su solicitud fue recibida.
    
    Args:
        coach_request: Instancia de CoachRequest con la información del solicitante
    """
    try:
        # Obtener configuración SMTP
        smtp_server = os.environ.get('SMTP_SERVER')
        smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        if not all([smtp_server, smtp_username, smtp_password]):
            logger.warning("⚠️ SMTP not configured - Confirmation email not sent")
            return False
        
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = coach_request.email
        msg['Subject'] = '✅ Solicitud de Coach Recibida - InstaCoach'
        
        # HTML body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #f9f9f9;">
                <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; text-align: center;">
                    <h1 style="margin: 0; font-size: 28px;">¡Gracias por tu interés!</h1>
                    <p style="margin: 10px 0 0 0; font-size: 16px;">Tu solicitud ha sido recibida exitosamente</p>
                </div>
                
                <div style="background: white; padding: 30px; border-radius: 0 0 8px 8px;">
                    <p style="font-size: 16px; margin-top: 0;">Hola <strong>{coach_request.full_name}</strong>,</p>
                    
                    <p>Hemos recibido tu solicitud para unirte a nuestro equipo de coaches en InstaCoach Assessment Platform.</p>
                    
                    <div style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #6366f1;">
                        <h3 style="color: #6366f1; margin-top: 0;">📋 Resumen de tu solicitud:</h3>
                        <ul style="list-style: none; padding: 0; margin: 10px 0;">
                            <li style="padding: 5px 0;"><strong>Nombre:</strong> {coach_request.full_name}</li>
                            <li style="padding: 5px 0;"><strong>Email:</strong> {coach_request.email}</li>
                            <li style="padding: 5px 0;"><strong>Usuario:</strong> {coach_request.username}</li>
                            <li style="padding: 5px 0;"><strong>Nivel de experiencia:</strong> {coach_request.experiencia or 'No especificado'}</li>
                        </ul>
                    </div>
                    
                    <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
                        <p style="margin: 0;"><strong>⏳ ¿Qué sigue?</strong></p>
                        <p style="margin: 10px 0 0 0;">Nuestro equipo revisará tu perfil y experiencia. Te contactaremos por este mismo email en un plazo de <strong>2-3 días hábiles</strong> con los siguientes pasos.</p>
                    </div>
                    
                    <p>Si tienes alguna pregunta mientras tanto, no dudes en contactarnos a <a href="mailto:support@instacoach.cl" style="color: #6366f1;">support@instacoach.cl</a></p>
                    
                    <p style="margin-top: 30px;">Saludos,<br><strong>Equipo InstaCoach</strong></p>
                </div>
                
                <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
                    <p>Este es un email automático, por favor no responder directamente.</p>
                    <p>© 2026 InstaCoach Assessment Platform</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version
        text_body = f"""
¡Gracias por tu interés en InstaCoach!

Hola {coach_request.full_name},

Hemos recibido tu solicitud para unirte a nuestro equipo de coaches en InstaCoach Assessment Platform.

RESUMEN DE TU SOLICITUD:
-------------------------
Nombre: {coach_request.full_name}
Email: {coach_request.email}
Usuario: {coach_request.username}
Nivel de experiencia: {coach_request.experiencia or 'No especificado'}

¿QUÉ SIGUE?
-----------
Nuestro equipo revisará tu perfil y experiencia. Te contactaremos por este mismo email en un plazo de 2-3 días hábiles con los siguientes pasos.

Si tienes alguna pregunta mientras tanto, no dudes en contactarnos a support@instacoach.cl

Saludos,
Equipo InstaCoach

---
Este es un email automático, por favor no responder directamente.
© 2026 InstaCoach Assessment Platform
        """.strip()
        
        msg.attach(MIMEText(html_body, 'html'))
        msg.attach(MIMEText(text_body, 'plain'))
        
        # Enviar email
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"📧 Email de confirmación enviado a {coach_request.email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error enviando email de confirmación: {str(e)}", exc_info=True)
        return False


def send_security_alert(event_type, details):
    """
    Envía alerta de seguridad por email cuando se detecta una amenaza.
    Falla silenciosamente si no está configurado SMTP.
    
    Args:
        event_type: Tipo de evento ('sustained_attack', 'account_locked', etc.)
        details: Diccionario con detalles del evento (ip_address, username, attempts, etc.)
    """
    try:
        # Verificar si las alertas están habilitadas
        enable_alerts = os.environ.get('ENABLE_SECURITY_ALERTS', 'true').lower() == 'true'
        if not enable_alerts:
            logger.debug("Security alerts disabled via ENABLE_SECURITY_ALERTS")
            return
        
        # Obtener configuración SMTP
        smtp_server = os.environ.get('SMTP_SERVER')
        smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        alert_email = os.environ.get('ALERT_EMAIL')
        
        # Si no hay configuración SMTP, solo registrar en log
        if not all([smtp_server, smtp_username, smtp_password, alert_email]):
            logger.info(f"Security alert [{event_type}]: {details} (SMTP not configured, logging only)")
            return
        
        # Verificar rate limit de alertas (max 1 alerta cada 5 minutos por IP)
        ip_address = details.get('ip_address', 'unknown')
        cache_key = f"alert_sent_{event_type}_{ip_address}"
        last_alert_time = getattr(send_security_alert, cache_key, None)
        
        if last_alert_time:
            time_since_last = datetime.utcnow() - last_alert_time
            if time_since_last < timedelta(minutes=5):
                logger.debug(f"Alert rate limit active for {ip_address}")
                return
        
        # Preparar mensaje de email
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = alert_email
        msg['Subject'] = f'🚨 Security Alert: {event_type.replace("_", " ").title()}'
        
        # Construir cuerpo del email
        body = f"""
        ALERTA DE SEGURIDAD - Assessment Platform
        ==========================================
        
        Tipo de Evento: {event_type.replace('_', ' ').upper()}
        Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        Detalles:
        ---------
        IP Address: {details.get('ip_address', 'N/A')}
        Username: {details.get('username', 'N/A')}
        Intentos Fallidos: {details.get('attempts', 'N/A')}
        Ventana de Tiempo: {details.get('time_window', 'N/A')}
        
        Descripción:
        {details.get('description', 'Se detectó actividad sospechosa en el sistema.')}
        
        Recomendaciones:
        - Revisar logs en SecurityLog para más detalles
        - Considerar bloqueo temporal de IP si continúa el ataque
        - Verificar si es un ataque de fuerza bruta coordinado
        
        ---
        Sistema de Monitoreo de Seguridad
        Assessment Platform
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Enviar email con timeout
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=5)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        # Registrar alerta enviada
        setattr(send_security_alert, cache_key, datetime.utcnow())
        logger.info(f"Security alert sent for {event_type} from IP {ip_address}")
        
        # Registrar en SecurityLog
        log_security_event(
            event_type='security_alert_sent',
            severity='warning',
            description=f"Alert sent for {event_type}",
            additional_data=str(details)
        )
        
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending security alert: {str(e)}")
    except Exception as e:
        logger.error(f"Error sending security alert: {str(e)}")
    # Falla silenciosamente - no debe interrumpir flujo de la aplicación

# ============================================================================
# FIN DE FUNCIONES DE AUDITORÍA Y ALERTAS
# ============================================================================

# ============================================================================
# FUNCIONES DE VALIDACIÓN DE URLs S3
# ============================================================================

def validate_s3_url(url, allowed_buckets=None):
    """
    Valida que una URL sea de un bucket S3 permitido.
    Previene ataques SSRF verificando que la URL pertenezca a buckets autorizados.
    
    Args:
        url: URL a validar
        allowed_buckets: Lista de nombres de buckets permitidos. Si None, usa AWS_S3_BUCKET
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    
    Ejemplos de URLs válidas:
        - https://efectocoach-avatars.s3.us-east-1.amazonaws.com/avatar.jpg
        - https://s3.us-east-1.amazonaws.com/efectocoach-avatars/avatar.jpg
    """
    try:
        from urllib.parse import urlparse
        
        # Si no se especifican buckets, usar el configurado en la app
        if allowed_buckets is None:
            aws_bucket = os.environ.get('AWS_S3_BUCKET', 'efectocoach-avatars')
            allowed_buckets = [aws_bucket] if aws_bucket else []
        
        if not allowed_buckets:
            # Si no hay buckets configurados, solo permitir URLs locales
            if url.startswith('/static/'):
                return (True, None)
            return (False, 'No hay buckets S3 configurados')
        
        # Validar que sea HTTPS
        if not url.startswith('https://'):
            # Permitir URLs locales (/static/)
            if url.startswith('/static/'):
                return (True, None)
            return (False, 'Solo se permiten URLs HTTPS o locales (/static/)')
        
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        path = parsed.path
        
        # Formato 1: bucket.s3.region.amazonaws.com
        # Ejemplo: efectocoach-avatars.s3.us-east-1.amazonaws.com
        for bucket in allowed_buckets:
            if hostname.startswith(f'{bucket}.s3.') and hostname.endswith('.amazonaws.com'):
                return (True, None)
        
        # Formato 2: s3.region.amazonaws.com/bucket/
        # Ejemplo: s3.us-east-1.amazonaws.com/efectocoach-avatars/
        if hostname.startswith('s3.') and hostname.endswith('.amazonaws.com'):
            # Verificar que el path empiece con alguno de los buckets permitidos
            for bucket in allowed_buckets:
                if path.startswith(f'/{bucket}/'):
                    return (True, None)
        
        # Formato 3: bucket.s3.amazonaws.com (sin región explícita)
        # Ejemplo: efectocoach-avatars.s3.amazonaws.com
        for bucket in allowed_buckets:
            if hostname == f'{bucket}.s3.amazonaws.com':
                return (True, None)
        
        return (False, f'URL no pertenece a un bucket S3 autorizado. Buckets permitidos: {", ".join(allowed_buckets)}')
        
    except Exception as e:
        logger.error(f"Error validating S3 URL: {str(e)}")
        return (False, f'Error al validar URL: {str(e)}')

# ============================================================================
# FIN DE FUNCIONES DE VALIDACIÓN S3
# ============================================================================

# ============================================================================
# FUNCIONES DE VALIDACIÓN Y CAMBIO DE CONTRASEÑAS
# ============================================================================

def validate_password_strength(password):
    """
    Valida que una contraseña cumpla con los requisitos mínimos de seguridad.
    
    Requisitos:
    - Mínimo 12 caracteres (mejorado de 8 para mayor seguridad)
    - Al menos 1 letra mayúscula
    - Al menos 1 letra minúscula
    - Al menos 1 número
    - Al menos 1 carácter especial (!@#$%^&*()_+-=[]{}|;:,.<>?)
    
    Args:
        password (str): Contraseña a validar
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not password or not isinstance(password, str):
        return (False, 'La contraseña es requerida')
    
    if len(password) < 12:
        return (False, 'La contraseña debe tener al menos 12 caracteres')
    
    if not re.search(r'[A-Z]', password):
        return (False, 'La contraseña debe contener al menos una letra mayúscula')
    
    if not re.search(r'[a-z]', password):
        return (False, 'La contraseña debe contener al menos una letra minúscula')
    
    if not re.search(r'\d', password):
        return (False, 'La contraseña debe contener al menos un número')
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        return (False, 'La contraseña debe contener al menos un carácter especial (!@#$%^&*()_+-=[]{}|;:,.<>?)')
    
    return (True, None)

def log_password_change(user_id, user_type, username=None):
    """
    Registra un cambio de contraseña en el SecurityLog.
    
    Args:
        user_id (int): ID del usuario
        user_type (str): Tipo de usuario ('admin', 'coach', 'coachee')
        username (str): Username o email del usuario (opcional)
    """
    try:
        log_security_event(
            event_type='password_changed',
            severity='info',
            user_id=user_id,
            username=username,
            description=f'Password changed successfully by {user_type} (ID: {user_id})'
        )
    except Exception as e:
        logger.error(f"Error logging password change: {str(e)}")

# ============================================================================
# FIN DE FUNCIONES DE VALIDACIÓN Y CAMBIO DE CONTRASEÑAS
# ============================================================================

# Función para versioning automático de archivos estáticos
def get_file_version(filename):
    """
    Genera automáticamente un número de versión basado en la fecha de modificación del archivo.
    Esto asegura que el navegador cargue siempre la versión más reciente.
    """
    try:
        file_path = os.path.join(app.static_folder, filename)
        if os.path.exists(file_path):
            # Obtener timestamp de modificación del archivo
            mtime = os.path.getmtime(file_path)
            # Convertir a formato legible (YYYYMMDDHHMMSS)
            return datetime.fromtimestamp(mtime).strftime('%Y%m%d%H%M%S')
        else:
            # Si el archivo no existe, usar timestamp actual
            return datetime.now().strftime('%Y%m%d%H%M%S')
    except Exception as e:
        logger.error(f"Error generando versión para {filename}: {str(e)}")
        # Fallback: usar timestamp actual
        return datetime.now().strftime('%Y%m%d%H%M%S')

# Funciones auxiliares para manejo de zona horaria
def get_santiago_now():
    """Obtener fecha y hora actual en zona horaria de Santiago"""
    return datetime.now(SANTIAGO_TZ)

def get_santiago_today():
    """Obtener fecha actual en zona horaria de Santiago"""
    return get_santiago_now().date()

def convert_to_santiago(utc_datetime):
    """Convertir datetime UTC a zona horaria de Santiago"""
    if utc_datetime is None:
        return None
    if utc_datetime.tzinfo is None:
        # Asumir que es UTC si no tiene zona horaria
        utc_datetime = pytz.UTC.localize(utc_datetime)
    return utc_datetime.astimezone(SANTIAGO_TZ)

def to_utc_for_db(santiago_datetime):
    """Convertir datetime de Santiago a UTC para guardar en base de datos"""
    if santiago_datetime is None:
        return None
    if isinstance(santiago_datetime, str):
        # Si es string, parsear primero
        santiago_datetime = datetime.strptime(santiago_datetime, '%Y-%m-%d')
    if santiago_datetime.tzinfo is None:
        # Si no tiene zona horaria, asumir que es Santiago
        santiago_datetime = SANTIAGO_TZ.localize(santiago_datetime)
    return santiago_datetime.astimezone(pytz.UTC).replace(tzinfo=None)

# Hacer la función disponible en todos los templates
@app.context_processor
def utility_processor():
    """Inyecta funciones útiles en todos los templates"""
    return dict(
        get_file_version=get_file_version,
        get_santiago_now=get_santiago_now,
        get_santiago_today=get_santiago_today,
        convert_to_santiago=convert_to_santiago
    )

# ============================================================================
# SECURITY HEADERS
# ============================================================================

@app.after_request
def add_security_headers(response):
    """
    Agrega headers de seguridad HTTP a todas las respuestas.
    Protege contra ataques comunes como XSS, clickjacking, MIME sniffing, etc.
    También optimiza caché para assets estáticos.
    """
    # ============================================================================
    # OPTIMIZACIÓN: CACHÉ PARA ASSETS ESTÁTICOS
    # ============================================================================
    # Permitir caché del navegador para archivos estáticos (CSS, JS, imágenes)
    # Esto reduce drásticamente el tiempo de carga en visitas repetidas
    if request.path.startswith('/static/'):
        # Caché de 1 año para assets con versionado (cambian el ?v=timestamp)
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        logger.debug(f"📦 Cache enabled for: {request.path}")
    
    # ============================================================================
    # SECURITY HEADERS
    # ============================================================================
    # X-Frame-Options: Previene clickjacking
    # DENY: no permite que el sitio sea embebido en iframes
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-Content-Type-Options: Previene MIME sniffing
    # nosniff: navegador debe respetar el Content-Type declarado
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-XSS-Protection: Protección XSS legacy (navegadores antiguos)
    # 1; mode=block: habilita filtro XSS y bloquea página si detecta ataque
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict-Transport-Security: Fuerza HTTPS (solo en producción)
    # max-age=31536000: válido por 1 año
    # includeSubDomains: aplica a todos los subdominios
    if IS_PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content-Security-Policy: Controla recursos que puede cargar la página
    # NOTA CRÍTICA: unsafe-inline y unsafe-eval necesarios para Alpine.js, FullCalendar y eventos del DOM
    # Eliminados generaría bloqueo total de la aplicación (setTimeout, onclick handlers, etc)
    csp_policy = (
        "default-src 'self'; "  # Por defecto, solo recursos del mismo origen
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' "  # Scripts completos (necesario para app funcional)
        "https://cdn.jsdelivr.net "  # FullCalendar CDN y Alpine.js
        "https://cdnjs.cloudflare.com "  # Chart.js, PDF.js y otras librerías
        "https://unpkg.com; "  # Alpine.js CDN alternativo
        "style-src 'self' 'unsafe-inline' "  # Estilos: mismo origen + inline (necesario para estilos dinámicos)
        "https://cdn.jsdelivr.net "  # FullCalendar CSS
        "https://cdnjs.cloudflare.com "  # Font Awesome y otros
        "https://fonts.googleapis.com; "  # Google Fonts
        "font-src 'self' "  # Fuentes: mismo origen
        "https://cdnjs.cloudflare.com "  # Font Awesome
        "https://fonts.gstatic.com "  # Google Fonts
        "data:; "  # Data URIs para fuentes embebidas
        "img-src 'self' data: https: blob:; "  # Imágenes: mismo origen + data URIs + HTTPS (para avatares S3)
        "connect-src 'self' https://www.youtube.com https://youtube.com https://www.instagram.com https://instagram.com; "  # Conexiones AJAX + YouTube/Instagram oEmbed API
        "frame-src 'self' https://www.youtube.com https://youtube.com https://www.instagram.com https://instagram.com; "  # Permitir embeds de YouTube e Instagram
        "worker-src 'self' blob:; "  # Permite Web Workers para PDF.js
        "frame-ancestors 'none'; "  # No permitir ser embebido en iframes (complementa X-Frame-Options)
        "base-uri 'self'; "  # Base URI solo mismo origen
        "form-action 'self'"  # Formularios solo pueden enviar a mismo origen
    )
    response.headers['Content-Security-Policy'] = csp_policy
    
    # Referrer-Policy: Controla información de referrer enviada
    # strict-origin-when-cross-origin: envía URL completa en mismo origen, solo origen en cross-origin HTTPS
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions-Policy: Controla APIs del navegador disponibles
    # Deshabilita APIs no necesarias para reducir superficie de ataque
    response.headers['Permissions-Policy'] = (
        'geolocation=(), '  # No necesitamos geolocalización
        'microphone=(), '  # No necesitamos micrófono
        'camera=(), '  # No necesitamos cámara
        'payment=(), '  # No procesamos pagos
        'usb=(), '  # No usamos USB
        'magnetometer=(), '  # No necesitamos magnetómetro
        'gyroscope=(), '  # No necesitamos giroscopio
        'accelerometer=()'  # No necesitamos acelerómetro
    )
    
    return response

# ============================================================================
# FIN DE SECURITY HEADERS
# ============================================================================

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        # Determinar la URL de redirección según la ruta del API
        redirect_url = '/participant-access'
        
        if '/api/admin' in request.path or '/api/platform-admin' in request.path:
            redirect_url = '/admin-login'
        elif '/api/coach' in request.path:
            redirect_url = '/coach-login'
        elif '/api/coachee' in request.path:
            redirect_url = '/participant-access'
        
        return jsonify({
            'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.',
            'redirect_url': redirect_url,
            'session_expired': True
        }), 401
    
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
    avatar_url = db.Column(db.String(500), nullable=True)  # URL del avatar del usuario
    role = db.Column(db.String(20), default='coachee', index=True)
    active = db.Column(db.Boolean, default=True, index=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    coach_notes = db.Column(db.Text, nullable=True)  # Notas del coach sobre el coachee (JSON array)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime, index=True)
    
    # Campos para soft delete
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)  # Fecha de eliminación
    deleted_by = db.Column(db.Integer, nullable=True)  # ID del admin que eliminó
    deletion_reason = db.Column(db.Text, nullable=True)  # Razón de eliminación
    
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

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_token'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used = db.Column(db.Boolean, default=False, index=True)
    
    user = db.relationship('User', backref='reset_tokens')
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        if 'created_at' not in kwargs:
            self.created_at = datetime.utcnow()
        if 'expires_at' not in kwargs:
            self.expires_at = datetime.utcnow() + timedelta(hours=1)  # Token válido por 1 hora
    
    def is_valid(self):
        """Verifica si el token sigue siendo válido"""
        return not self.used and datetime.utcnow() < self.expires_at

class CoachRequest(db.Model):
    __tablename__ = 'coach_request'
    
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, index=True)
    username = db.Column(db.String(80), nullable=False)
    areas = db.Column(db.Text, nullable=True)  # JSON array de áreas de expertise
    experiencia = db.Column(db.String(50), nullable=True)
    estilo = db.Column(db.String(50), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    activation_token = db.Column(db.String(100), unique=True, nullable=True, index=True)  # Token para activación
    activation_expires = db.Column(db.DateTime, nullable=True)  # Expiración del token
    
    reviewer = db.relationship('User', backref='reviewed_coach_requests')
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        if 'created_at' not in kwargs:
            self.created_at = datetime.utcnow()

class Assessment(db.Model):
    __tablename__ = 'assessment'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='published')  # 'draft' o 'published'
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Coach creador
    category = db.Column(db.String(100), nullable=True)  # Categoría de la evaluación
    
    questions = db.relationship('Question', backref='assessment', lazy=True, cascade='all, delete-orphan')
    results = db.relationship('AssessmentResult', backref='assessment_ref', lazy=True)
    creator = db.relationship('User', backref='created_assessments', foreign_keys=[coach_id])

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
    score_history = db.Column(db.JSON, nullable=True, default=list)  # Historial de intentos
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='supervised_assessments')
    invitation = db.relationship('Invitation', backref='assessment_results')
    
    __table_args__ = (
        db.Index('idx_user_assessment', 'user_id', 'assessment_id'),
        db.Index('idx_coach_completed', 'coach_id', 'completed_at'),
        db.UniqueConstraint('user_id', 'assessment_id', name='uq_user_assessment'),
    )

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.completed_at = kwargs.get('completed_at', datetime.utcnow())

class AssessmentHistory(db.Model):
    """Tabla para almacenar el historial completo de todos los intentos de evaluación"""
    __tablename__ = 'assessment_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    score = db.Column(db.Float)
    total_questions = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    result_text = db.Column(db.Text)
    dimensional_scores = db.Column(db.JSON, nullable=True)
    attempt_number = db.Column(db.Integer, default=1)  # Número de intento para esta evaluación
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    
    # Relaciones
    user = db.relationship('User', foreign_keys=[user_id], backref='assessment_history')
    assessment = db.relationship('Assessment', foreign_keys=[assessment_id])
    coach = db.relationship('User', foreign_keys=[coach_id])
    
    __table_args__ = (
        db.Index('idx_history_user', 'user_id'),
        db.Index('idx_history_assessment', 'assessment_id'),
        db.Index('idx_history_completed', 'completed_at'),
        db.Index('idx_history_user_assessment', 'user_id', 'assessment_id'),
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
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=True, index=True)
    accepted_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='pending')
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='sent_invitations')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_invitation')
    assessment = db.relationship('Assessment', foreign_keys=[assessment_id], backref='invitations')
    
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
    type = db.Column(db.String(20), default='accion')
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

class DevelopmentPlan(db.Model):
    __tablename__ = 'development_plan'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=True)  # Referencia a la solicitud
    
    # Contenido del plan
    objetivo = db.Column(db.Text, nullable=False)
    situacion_actual = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(20), default='personal')  # personal, professional
    areas_desarrollo = db.Column(db.JSON, nullable=False)  # Array de strings
    acciones = db.Column(db.JSON, nullable=False)  # Array de objetos {descripcion, frecuencia, fecha_objetivo, completed}
    milestones = db.Column(db.JSON, nullable=True)  # Array de objetos {id, title, description, completed, completed_at}
    indicadores = db.Column(db.Text, nullable=True)
    
    # Estado y metadata
    status = db.Column(db.String(20), default='draft')  # draft, published, in_progress, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = db.Column(db.DateTime, nullable=True)
    
    # Relaciones
    coach = db.relationship('User', foreign_keys=[coach_id], backref='created_development_plans')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='development_plans')
    request_task = db.relationship('Task', foreign_keys=[request_task_id])

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        now = datetime.utcnow()
        self.created_at = kwargs.get('created_at', now)
        self.updated_at = kwargs.get('updated_at', now)

class Notification(db.Model):
    __tablename__ = 'notification'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)  # session_request, evaluation_completed, content_assigned, etc.
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    related_id = db.Column(db.Integer, nullable=True)  # ID del objeto relacionado
    related_type = db.Column(db.String(50), nullable=True)  # tipo del objeto relacionado
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', backref='notifications')
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'title': self.title,
            'message': self.message,
            'related_id': self.related_id,
            'related_type': self.related_type,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Content(db.Model):
    __tablename__ = 'content'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # NULL = biblioteca, no asignado
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    content_type = db.Column(db.String(50), default='video')  # video, document, article
    content_url = db.Column(db.String(500), nullable=False)  # URL del video o archivo
    thumbnail_url = db.Column(db.String(500), nullable=True)
    duration = db.Column(db.Integer, nullable=True)  # duración en segundos
    is_viewed = db.Column(db.Boolean, default=False)
    viewed_at = db.Column(db.DateTime, nullable=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # NUEVOS CAMPOS PARA COMUNIDADES - COMENTADOS: No existen en producción
    # community_id = db.Column(db.Integer, db.ForeignKey('coach_community.id'), nullable=True, index=True)  # comunidad donde se comparte
    # shared_with_community = db.Column(db.Boolean, default=False, index=True)  # si está compartido en comunidad
    # shared_at = db.Column(db.DateTime, nullable=True)  # cuándo se compartió
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='assigned_content')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_content')

    def __init__(self, **kwargs):
        # Solo asignar atributos que existen en la base de datos
        # Ignorar community_id, shared_with_community, shared_at si no existen
        valid_attrs = ['id', 'coach_id', 'coachee_id', 'title', 'description', 
                      'content_type', 'content_url', 'thumbnail_url', 'duration',
                      'is_viewed', 'viewed_at', 'assigned_at', 'is_active']
        
        for key, value in kwargs.items():
            if key in valid_attrs or hasattr(self, key):
                setattr(self, key, value)
        
        self.assigned_at = kwargs.get('assigned_at', datetime.utcnow())
    
    def mark_as_viewed(self):
        self.is_viewed = True
        self.viewed_at = datetime.utcnow()

class CoachAvailability(db.Model):
    __tablename__ = 'coach_availability'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    day_of_week = db.Column(db.Integer, nullable=False)  # 0=Domingo, 1=Lunes, etc.
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    coach = db.relationship('User', backref='availability_slots')

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())

class CoachingSession(db.Model):
    __tablename__ = 'coaching_session'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)  # Nullable para actividades del coach
    session_date = db.Column(db.Date, nullable=False, index=True)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, confirmed, cancelled, completed, proposed
    title = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(200), nullable=True)  # Zoom, presencial, etc.
    notes = db.Column(db.Text, nullable=True)  # Notas adicionales
    
    # Para propuestas de horario alternativo
    original_session_id = db.Column(db.Integer, db.ForeignKey('coaching_session.id'), nullable=True)
    proposed_by = db.Column(db.String(20), nullable=True)  # 'coach' o 'coachee'
    proposal_message = db.Column(db.Text, nullable=True)
    
    # Nuevos campos para gestión de citas
    session_type = db.Column(db.String(50), default='coaching', index=True)  # coaching, self_activity, direct_appointment
    activity_type = db.Column(db.String(50), nullable=True)  # preparation, admin, break, training, meeting, personal, other
    activity_title = db.Column(db.String(200), nullable=True)  # Título de la actividad para autoagenda
    activity_description = db.Column(db.Text, nullable=True)  # Descripción de la actividad
    is_recurring = db.Column(db.Boolean, default=False)  # Si es una actividad recurrente
    created_by_coach = db.Column(db.Boolean, default=False)  # Si fue creada directamente por el coach
    notification_message = db.Column(db.Text, nullable=True)  # Mensaje personalizado de notificación
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='coaching_sessions_as_coach')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='coaching_sessions_as_coachee')
    original_session = db.relationship('CoachingSession', remote_side=[id], backref='proposals')

    @property
    def coachee_name(self):
        """Obtener el nombre del coachee para mostrar en el calendario"""
        return self.coachee.full_name if self.coachee else 'Sin nombre'

    @property
    def session_datetime(self):
        """Combinar fecha y hora de inicio para el calendario"""
        return datetime.combine(self.session_date, self.start_time)

    @property
    def session_end_datetime(self):
        """Combinar fecha y hora de fin para el calendario"""
        return datetime.combine(self.session_date, self.end_time)

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())
        self.updated_at = kwargs.get('updated_at', datetime.utcnow())


class SessionRequest(db.Model):
    """Solicitudes de sesión gratuita de coachees"""
    __tablename__ = 'session_request'
    
    id = db.Column(db.Integer, primary_key=True)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    evaluation_id = db.Column(db.Integer, nullable=True, index=True)  # De AssessmentHistory o AssessmentResult
    session_type = db.Column(db.String(50), default='free_consultation')
    
    # Información de contacto
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    whatsapp = db.Column(db.String(50), nullable=True)
    preferred_method = db.Column(db.String(20), default='email')  # email, phone, whatsapp
    
    # Información adicional
    availability = db.Column(db.Text, nullable=True)
    message = db.Column(db.Text, nullable=True)
    
    # Estado de la solicitud
    status = db.Column(db.String(20), default='pending', index=True)  # pending, contacted, scheduled, completed, cancelled
    
    # Coach asignado (opcional)
    assigned_coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    
    # Notas del coach
    coach_notes = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    contacted_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='session_requests')
    assigned_coach = db.relationship('User', foreign_keys=[assigned_coach_id], backref='assigned_session_requests')

# ============================================================================
# MODELO DE AUDITORÍA DE SEGURIDAD
# ============================================================================

class SecurityLog(db.Model):
    """
    Modelo para registro de eventos de seguridad.
    Registra eventos críticos como logins fallidos, accesos no autorizados,
    cambios de contraseña, y otras actividades sospechosas.
    """
    __tablename__ = 'security_log'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Información del evento
    event_type = db.Column(db.String(50), nullable=False, index=True)
    # Tipos: 'login_failed', 'login_success', 'unauthorized_access', 
    #        'password_change', 'account_locked', 'suspicious_activity',
    #        'rate_limit_exceeded', 'invalid_token', 'session_hijack_attempt'
    
    severity = db.Column(db.String(20), nullable=False, index=True)
    # Niveles: 'info', 'warning', 'error', 'critical'
    
    # Información del usuario
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    username = db.Column(db.String(120), nullable=True, index=True)  # Guardado por si usuario no existe
    user_role = db.Column(db.String(20), nullable=True)
    
    # Información de la solicitud
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv4 o IPv6
    user_agent = db.Column(db.String(500), nullable=True)
    endpoint = db.Column(db.String(200), nullable=True, index=True)
    method = db.Column(db.String(10), nullable=True)  # GET, POST, PUT, DELETE
    
    # Detalles del evento
    description = db.Column(db.Text, nullable=True)
    additional_data = db.Column(db.Text, nullable=True)  # JSON string con datos adicionales
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relación con usuario (si existe)
    user = db.relationship('User', backref='security_logs', foreign_keys=[user_id])
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.created_at = kwargs.get('created_at', datetime.utcnow())
    
    def __repr__(self):
        return f'<SecurityLog {self.event_type} - {self.severity} - {self.created_at}>'

# ============================================================================
# FIN DE MODELO DE AUDITORÍA
# ============================================================================

# ============================================================================
# MODELO: Registro de Sesiones de Coaching
# ============================================================================
class SessionRecord(db.Model):
    """Registro estructurado de sesiones de coaching (Sesión Cero, Sesión 1, etc.)"""
    __tablename__ = 'session_record'

    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    session_number = db.Column(db.Integer, nullable=False)  # 0=Sesión Cero, 1=Sesión 1, ...
    name = db.Column(db.String(200), nullable=False)        # Nombre editable
    objective = db.Column(db.Text, nullable=True)           # Objetivo de la sesión
    participants = db.Column(db.Text, nullable=True)        # JSON: lista de coachee IDs
    content = db.Column(db.Text, nullable=True)             # Contenido/notas de la sesión
    commitments = db.Column(db.Text, nullable=True)         # JSON: lista de compromisos con fechas
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    coach = db.relationship('User', foreign_keys=[coach_id], backref='session_records')

# ============================================================================
# FIN MODELO SessionRecord
# ============================================================================

# ============================================================================
# MODELO: Contratos de Suscripción
# ============================================================================
class SubscriptionContract(db.Model):
    """Contrato enviado por el coach al coachee para suscripción"""
    __tablename__ = 'subscription_contract'

    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    filename = db.Column(db.String(300), nullable=False)        # Nombre original del archivo
    file_path = db.Column(db.String(500), nullable=False)       # Ruta local o URL S3
    num_sessions = db.Column(db.Integer, nullable=True)         # Número de sesiones contratadas
    summary = db.Column(db.Text, nullable=True)                 # Resumen del contrato
    status = db.Column(db.String(30), default='pending', index=True)  # pending, signed, payment_pending, active
    sent_at = db.Column(db.DateTime, nullable=True)
    signed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    coach = db.relationship('User', foreign_keys=[coach_id], backref='contracts_as_coach')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='contracts_as_coachee')

# ============================================================================
# FIN MODELO SubscriptionContract
# ============================================================================

# ============================================================================
# MODELO: Acuerdo de Compromiso de Coaching
# ============================================================================
class CoachingAgreement(db.Model):
    """Acuerdo de compromiso generado por el coach para un coachee"""
    __tablename__ = 'coaching_agreement'

    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)  # Puede ser null si se ingresa manualmente
    status = db.Column(db.String(20), default='borrador', index=True)  # borrador, enviado, firmado
    contract_data = db.Column(db.Text, nullable=True)   # JSON con todos los campos del formulario
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    coach = db.relationship('User', foreign_keys=[coach_id], backref='coaching_agreements_as_coach')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='coaching_agreements_as_coachee')

# ============================================================================
# FIN MODELO CoachingAgreement
# ============================================================================

# Modelos para el sistema de documentos
class Document(db.Model):
    __tablename__ = 'document'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    coachee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, index=True)  # ejercicios, teoria, evaluacion, etc.
    priority = db.Column(db.String(20), default='normal', index=True)  # normal, alta, urgente
    notify_coachee = db.Column(db.Boolean, default=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    coach = db.relationship('User', foreign_keys=[coach_id], backref='uploaded_documents')
    coachee = db.relationship('User', foreign_keys=[coachee_id], backref='received_documents')
    files = db.relationship('DocumentFile', backref='document', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.uploaded_at = kwargs.get('uploaded_at', datetime.utcnow())

class DocumentFile(db.Model):
    __tablename__ = 'document_file'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

# ============================================================================
# MODELOS PARA SISTEMA DE COMUNIDADES DE COACHES
# ============================================================================

class CoachCommunity(db.Model):
    """
    Modelo para comunidades de coaches.
    Permite a coaches crear y gestionar comunidades para compartir contenido.
    """
    __tablename__ = 'coach_community'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.Text, nullable=True)  # URL de la imagen (catálogo o subida)
    image_type = db.Column(db.String(20), default='catalog')  # emoji, catalog, upload
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, index=True)
    privacy = db.Column(db.String(20), default='private', index=True)  # private, public
    
    # Relaciones
    creator = db.relationship('User', foreign_keys=[creator_id], backref='created_communities')
    memberships = db.relationship('CommunityMembership', backref='community', lazy='dynamic', cascade='all, delete-orphan')
    # shared_content = db.relationship('Content', backref='community', lazy='dynamic')  # COMENTADO: Content.community_id no existe en producción
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'image_url': self.image_url,
            'image_type': self.image_type,
            'creator_id': self.creator_id,
            'creator_name': self.creator.full_name if self.creator else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active,
            'privacy': self.privacy,
            'member_count': self.memberships.filter_by(is_active=True).count()
        }

class CommunityMembership(db.Model):
    """
    Modelo para membresía de coaches en comunidades.
    Gestiona roles y permisos dentro de cada comunidad.
    """
    __tablename__ = 'community_membership'
    
    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('coach_community.id'), nullable=False, index=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    role = db.Column(db.String(20), default='member', index=True)  # admin, moderator, member
    joined_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Relaciones
    coach = db.relationship('User', foreign_keys=[coach_id], backref='community_memberships')
    
    __table_args__ = (
        db.UniqueConstraint('community_id', 'coach_id', name='uq_community_coach'),
        db.Index('idx_community_active', 'community_id', 'is_active'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'community_id': self.community_id,
            'coach_id': self.coach_id,
            'coach_name': self.coach.full_name if self.coach else None,
            'coach_email': self.coach.email if self.coach else None,
            'coach_avatar': self.coach.avatar_url if self.coach else None,
            'role': self.role,
            'joined_at': self.joined_at.isoformat() if self.joined_at else None,
            'is_active': self.is_active
        }

class CommunityInvitation(db.Model):
    """
    Modelo para invitaciones a comunidades de coaches.
    Gestiona invitaciones mediante link - NO crea acceso automático.
    El invitado debe registrarse por su cuenta en coach-login.
    """
    __tablename__ = 'community_invitation'
    
    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('coach_community.id'), nullable=False, index=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)  # quien invita
    invitee_email = db.Column(db.String(120), nullable=True, index=True)  # email del invitado (opcional si usa phone)
    invitee_phone = db.Column(db.String(30), nullable=True, index=True)  # teléfono del invitado (WhatsApp/SMS)
    invitee_name = db.Column(db.String(200), nullable=True)  # nombre opcional del invitado
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)  # token único para el link
    message = db.Column(db.Text, nullable=True)  # mensaje personalizado opcional
    invitation_method = db.Column(db.String(20), default='email')  # 'email', 'whatsapp', 'sms'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)  # expiración del link
    accepted_at = db.Column(db.DateTime, nullable=True)  # cuándo se aceptó
    is_used = db.Column(db.Boolean, default=False, index=True)  # si ya se usó el link
    accepted_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)  # quien aceptó
    
    # Relaciones
    community = db.relationship('CoachCommunity', backref='invitations')
    inviter = db.relationship('User', foreign_keys=[inviter_id], backref='sent_community_invitations')
    accepted_by = db.relationship('User', foreign_keys=[accepted_by_user_id], backref='accepted_community_invitations')
    
    __table_args__ = (
        db.Index('idx_invitation_email_community', 'invitee_email', 'community_id'),
    )
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        if 'created_at' not in kwargs:
            self.created_at = datetime.utcnow()
        if 'expires_at' not in kwargs:
            self.expires_at = datetime.utcnow() + timedelta(days=7)  # expira en 7 días
        if 'token' not in kwargs:
            self.token = secrets.token_urlsafe(32)
    
    def is_valid(self):
        """Verifica si la invitación sigue siendo válida"""
        return not self.is_used and datetime.utcnow() < self.expires_at
    
    def mark_as_used(self, user_id):
        """Marca la invitación como usada"""
        self.is_used = True
        self.accepted_at = datetime.utcnow()
        self.accepted_by_user_id = user_id
    
    def to_dict(self):
        return {
            'id': self.id,
            'community_id': self.community_id,
            'community_name': self.community.name if self.community else None,
            'inviter_name': self.inviter.full_name if self.inviter else None,
            'invitee_email': self.invitee_email,
            'invitee_name': self.invitee_name,
            'message': self.message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_used': self.is_used,
            'is_valid': self.is_valid()
        }

# ============================================================================
# FIN DE MODELOS DE COMUNIDADES
# ============================================================================
        self.uploaded_at = kwargs.get('uploaded_at', datetime.utcnow())

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Funciones auxiliares optimizadas
def get_current_coachee():
    """Obtiene el usuario coachee actual"""
    # PRIMERO: Verificar g.current_user (establecido por decoradores)
    if hasattr(g, 'current_user') and g.current_user and g.current_user.role == 'coachee':
        return g.current_user
    
    # SEGUNDO: Verificar sesión independiente de coachee (método principal)
    if coachee_user_id := session.get('coachee_user_id'):
        user = db.session.get(User, coachee_user_id)
        if user and user.role == 'coachee':
            return user
    
    # TERCERO: Verificar Flask-Login (solo si es seguro acceder)
    try:
        if current_user.is_authenticated and current_user.role == 'coachee':
            return current_user
    except Exception:
        # Si hay error accediendo a current_user, continuar con otros métodos
        pass
    
    # CUARTO: Verificar sesión temporal de coachee
    if temp_coachee_id := session.get('temp_coachee_id'):
        return db.session.get(User, temp_coachee_id)
    return None

def create_decorator(required_condition, error_message, redirect_func=None):
    """Factory para crear decoradores de autorización"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not required_condition():
                # Registrar intento de acceso no autorizado
                user_id = current_user.id if current_user.is_authenticated else None
                username = current_user.username if current_user.is_authenticated else None
                log_unauthorized_access(user_id=user_id, username=username, required_role=error_message)
                
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
            return jsonify({
                'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.',
                'redirect_url': '/login',
                'session_expired': True
            }), 401
        kwargs['current_coachee'] = coachee_user
        return f(*args, **kwargs)
    return decorated_function

def coach_session_required(f):
    """Decorador específico para APIs de coach que valida sesión independiente"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        coach_user_id = session.get('coach_user_id')
        
        # Detectar si es petición de API (JSON) o HTML
        is_api_request = (
            request.path.startswith('/api/') or 
            request.headers.get('Accept', '').find('application/json') != -1 or
            request.headers.get('Content-Type', '').find('application/json') != -1 or
            request.method in ['PUT', 'DELETE', 'PATCH']
        )
        
        if not coach_user_id:
            log_unauthorized_access(required_role='coach')
            
            # Si es petición HTML, redirigir al login
            if not is_api_request:
                flash('Tu sesión ha expirado. Por favor, inicia sesión nuevamente.', 'warning')
                return redirect(url_for('coach_login_page'))
            
            # Si es API, retornar JSON
            return jsonify({
                'error': 'Sesión de coach expirada. Por favor, inicia sesión nuevamente.',
                'redirect_url': '/coach-login',
                'session_expired': True
            }), 401
        
        # Verificar que el usuario existe y es coach
        coach_user = User.query.get(coach_user_id)
        if not coach_user or coach_user.role != 'coach':
            log_unauthorized_access(user_id=coach_user_id, required_role='coach')
            session.pop('coach_user_id', None)
            
            # Si es petición HTML, redirigir al login
            if not is_api_request:
                flash('Usuario de coach inválido. Por favor, inicia sesión nuevamente.', 'warning')
                return redirect(url_for('coach_login_page'))
            
            # Si es API, retornar JSON
            return jsonify({
                'error': 'Usuario de coach inválido.',
                'redirect_url': '/coach-login',
                'session_expired': True
            }), 401
        
        # Establecer current_user para esta petición sin usar Flask-Login
        g.current_user = coach_user
        return f(*args, **kwargs)
    return decorated_function

def coachee_session_required(f):
    """Decorador específico para APIs de coachee que valida sesión independiente"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        coachee_user_id = session.get('coachee_user_id')
        
        # Detectar si es petición de API (JSON) o HTML
        is_api_request = (
            request.path.startswith('/api/') or 
            request.headers.get('Accept', '').find('application/json') != -1 or
            request.headers.get('Content-Type', '').find('application/json') != -1 or
            request.method in ['PUT', 'DELETE', 'PATCH']
        )
        
        if not coachee_user_id:
            # Si es petición HTML, redirigir al login
            if not is_api_request:
                flash('Tu sesión ha expirado. Por favor, inicia sesión nuevamente.', 'warning')
                return redirect(url_for('participant_access'))
            
            # Si es API, retornar JSON
            return jsonify({
                'error': 'Sesión de coachee expirada. Por favor, inicia sesión nuevamente.',
                'redirect_url': '/participant-access',
                'session_expired': True
            }), 401
        
        # Verificar que el usuario existe y es coachee
        coachee_user = User.query.get(coachee_user_id)
        if not coachee_user or coachee_user.role != 'coachee':
            session.pop('coachee_user_id', None)
            
            # Si es petición HTML, redirigir al login
            if not is_api_request:
                flash('Usuario de coachee inválido. Por favor, inicia sesión nuevamente.', 'warning')
                return redirect(url_for('participant_access'))
            
            # Si es API, retornar JSON
            return jsonify({
                'error': 'Usuario de coachee inválido.',
                'redirect_url': '/participant-access',
                'session_expired': True
            }), 401
        
        # Establecer current_user para esta petición sin usar Flask-Login
        g.current_user = coachee_user
        return f(*args, **kwargs)
    return decorated_function

def either_session_required(f):
    """Decorador que permite tanto sesión de coach como de coachee"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = None
        
        # PRIORIDAD BASADA EN LA RUTA:
        # Si la ruta incluye 'coachee', priorizar sesión de coachee
        # Si la ruta incluye 'coach', priorizar sesión de coach
        # De lo contrario, mantener prioridad coach (comportamiento anterior)
        
        route_path = request.path
        prioritize_coachee = '/coachee' in route_path or '/participant' in route_path
        
        if prioritize_coachee:
            # PRIORIDAD 1: Verificar sesión de coachee
            if 'coachee_user_id' in session:
                coachee_id = session['coachee_user_id']
                user = User.query.get(coachee_id)
                if user and user.role == 'coachee':
                    current_user = user
            
            # PRIORIDAD 2: Si no hay sesión de coachee, verificar sesión de coach
            if not current_user and 'coach_user_id' in session:
                coach_id = session['coach_user_id']
                user = User.query.get(coach_id)
                if user and user.role == 'coach':
                    current_user = user
        else:
            # PRIORIDAD 1: Verificar sesión de coach
            if 'coach_user_id' in session:
                coach_id = session['coach_user_id']
                user = User.query.get(coach_id)
                if user and user.role == 'coach':
                    current_user = user
            
            # PRIORIDAD 2: Si no hay sesión de coach, verificar sesión de coachee
            if not current_user and 'coachee_user_id' in session:
                coachee_id = session['coachee_user_id']
                user = User.query.get(coachee_id)
                if user and user.role == 'coachee':
                    current_user = user
        
        if not current_user:
            return jsonify({
                'error': 'No autorizado. Debe iniciar sesión.',
                'redirect_url': '/login',
                'session_expired': True
            }), 401
        
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
    """Cargar el usuario actual y validar actividad reciente"""
    # Limpiar g.current_user al inicio de cada request
    g.current_user = None
    
    # VALIDACIÓN DE ACTIVIDAD RECIENTE (2 horas de inactividad = logout automático)
    current_time = datetime.utcnow()
    inactivity_limit = timedelta(hours=2)
    
    # Validar sesión de admin (Flask-Login)
    if current_user.is_authenticated and current_user.role == 'platform_admin':
        last_activity_admin = session.get('last_activity_admin')
        if last_activity_admin:
            try:
                last_activity_time = datetime.fromisoformat(last_activity_admin)
                if current_time - last_activity_time > inactivity_limit:
                    # Sesión de admin expirada por inactividad
                    logger.info(f"Admin session expired due to inactivity (user: {current_user.username})")
                    logout_user()
                    session.clear()
                    return redirect(url_for('admin_login_page'))
                else:
                    # Actualizar timestamp solo si no expiró
                    session['last_activity_admin'] = current_time.isoformat()
            except (ValueError, TypeError):
                # Si hay error al parsear, inicializar timestamp
                session['last_activity_admin'] = current_time.isoformat()
        else:
            # Si no existe timestamp, inicializarlo
            session['last_activity_admin'] = current_time.isoformat()
    
    # Validar sesión de coach (independiente)
    if 'coach_user_id' in session:
        last_activity_coach = session.get('last_activity_coach')
        if last_activity_coach:
            try:
                last_activity_time = datetime.fromisoformat(last_activity_coach)
                if current_time - last_activity_time > inactivity_limit:
                    # Sesión de coach expirada por inactividad
                    coach_id = session.get('coach_user_id')
                    # Limpiar solo las claves de coach (no session.clear() para evitar conflictos)
                    session.pop('coach_user_id', None)
                    session.pop('last_activity_coach', None)
                    logger.info(f"Coach session expired due to inactivity (coach_id: {coach_id})")
                    return redirect(url_for('coach_login_page'))
                else:
                    # Actualizar timestamp solo si no expiró
                    session['last_activity_coach'] = current_time.isoformat()
            except (ValueError, TypeError):
                # Si hay error al parsear, inicializar timestamp
                session['last_activity_coach'] = current_time.isoformat()
        else:
            # Si no existe timestamp, inicializarlo
            session['last_activity_coach'] = current_time.isoformat()
    
    # Validar sesión de coachee (independiente)
    if 'coachee_user_id' in session:
        last_activity_coachee = session.get('last_activity_coachee')
        if last_activity_coachee:
            try:
                last_activity_time = datetime.fromisoformat(last_activity_coachee)
                if current_time - last_activity_time > inactivity_limit:
                    # Sesión de coachee expirada por inactividad
                    coachee_id = session.get('coachee_user_id')
                    # Limpiar solo las claves de coachee (no session.clear() para evitar conflictos)
                    session.pop('coachee_user_id', None)
                    session.pop('last_activity_coachee', None)
                    session.pop('temp_coachee_id', None)
                    logger.info(f"Coachee session expired due to inactivity (coachee_id: {coachee_id})")
                    return redirect(url_for('participant_access'))
                else:
                    # Actualizar timestamp solo si no expiró
                    session['last_activity_coachee'] = current_time.isoformat()
            except (ValueError, TypeError):
                # Si hay error al parsear, inicializar timestamp
                session['last_activity_coachee'] = current_time.isoformat()
        else:
            # Si no existe timestamp, inicializarlo
            session['last_activity_coachee'] = current_time.isoformat()
    
    # No establecer g.current_user aquí para evitar conflictos.
    # Cada decorador específico (@coach_session_required, @coachee_session_required) 
    # será responsable de establecer g.current_user basado en su sesión específica.

admin_required = create_decorator(
    lambda: current_user.is_authenticated and current_user.role == 'platform_admin',
    'Acceso denegado. Solo administradores pueden acceder a esta función.'
)

def coach_required(f):
    """Decorador que verifica si el usuario es coach (usando sesión de coach)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # DEBUG: Log session state
        logger.info(f"🔍 DEBUG @coach_required - Path: {request.path}, Session keys: {list(session.keys())}, coach_user_id: {session.get('coach_user_id')}")
        
        # Verificar si hay sesión de coach activa
        if 'coach_user_id' not in session:
            logger.warning(f"❌ DEBUG @coach_required - NO coach_user_id in session for {request.path}")
            log_unauthorized_access(username='Anonymous', required_role='coach')
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Autenticación requerida. Debes iniciar sesión como coach.'}), 401
            return redirect(url_for('coach_login_page'))
        
        # Cargar coach desde sesión
        coach_id = session.get('coach_user_id')
        coach = User.query.get(coach_id)
        
        if not coach or coach.role != 'coach':
            log_unauthorized_access(user_id=coach_id, username=coach.username if coach else None, required_role='coach')
            session.pop('coach_user_id', None)  # Limpiar sesión inválida
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Acceso denegado. Solo coaches pueden acceder a esta función.'}), 403
            return redirect(url_for('coach_login_page'))
        
        # Establecer g.current_user para uso en la función
        g.current_user = coach
        
        return f(*args, **kwargs)
    return decorated_function

# Inicialización automática de base de datos
def auto_initialize_database():
    """Inicialización automática completa para producción"""
    try:
        logger.info("🚀 AUTO-INICIALIZACIÓN: Verificando base de datos...")
        
        # Esperar un momento en caso de PostgreSQL
        import time
        time.sleep(1)
        
        # NO ejecutar db.create_all() incondicionalmente porque recrea tablas
        # Solo crear tablas si no existen
        # db.create_all()
        logger.info("✅ AUTO-INIT: Verificando tablas existentes (sin recrear)")
        
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
            logger.warning(f"🔧 AUTO-INIT: Tablas faltantes: {missing_tables}")
            logger.warning(f"⚠️ AUTO-INIT: NO se ejecutará db.create_all() - ejecute migraciones manualmente")
            # NO ejecutar db.create_all() porque recrea TODAS las tablas con schema cacheado
            # db.create_all()
            # time.sleep(2)
            
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
                logger.info("ℹ️ AUTO-INIT: Usuario admin ya existe - contraseña NO modificada")
                
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
        
        # Ejecutar migraciones automáticas
        run_auto_migrations()
        
        logger.info("🎉 AUTO-INIT: Inicialización completa finalizada")
        return True
        
    except Exception as e:
        logger.error(f"❌ AUTO-INIT: Error en inicialización automática: {e}")
        return False

def run_auto_migrations():
    """Ejecutar migraciones automáticas de esquema"""
    try:
        logger.info("🔧 MIGRACIONES: Verificando y aplicando migraciones...")
        
        # Detectar tipo de base de datos
        db_type = db.session.bind.dialect.name
        
        # Migración 1 y 2: Agregar columnas 'category' y 'milestones' a development_plan
        # Usar information_schema para verificación robusta (mismo patrón que coach_community)
        try:
            if db_type == 'postgresql':
                # PostgreSQL: consultar information_schema
                result = db.session.execute(text("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name='development_plan' AND column_name IN ('category', 'milestones')
                """))
                existing_columns = [row[0] for row in result]
            else:
                # SQLite: consultar pragma
                result = db.session.execute(text("PRAGMA table_info(development_plan)"))
                existing_columns = [row[1] for row in result if row[1] in ['category', 'milestones']]
            
            # Agregar category si no existe
            if 'category' not in existing_columns:
                db.session.execute(text("ALTER TABLE development_plan ADD COLUMN category VARCHAR(20) DEFAULT 'personal'"))
                db.session.commit()
                logger.info("✅ MIGRACIÓN: Campo 'category' agregado en development_plan")
            else:
                logger.info("ℹ️ MIGRACIÓN: Campo 'category' ya existe en development_plan")
            
            # Agregar milestones si no existe
            if 'milestones' not in existing_columns:
                db.session.execute(text("ALTER TABLE development_plan ADD COLUMN milestones TEXT"))
                db.session.commit()
                logger.info("✅ MIGRACIÓN: Campo 'milestones' agregado en development_plan")
            else:
                logger.info("ℹ️ MIGRACIÓN: Campo 'milestones' ya existe en development_plan")
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ MIGRACIÓN: Error en migración de development_plan: {e}", exc_info=True)
        
        # Migración 3: Agregar columnas 'image_url' e 'image_type' a coach_community
        # Verificación robusta: consultar esquema de la base de datos para ver si las columnas existen
        try:
            # Detectar si es PostgreSQL o SQLite
            db_type = db.session.bind.dialect.name
            
            if db_type == 'postgresql':
                # PostgreSQL: consultar information_schema
                result = db.session.execute(text("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name='coach_community' AND column_name IN ('image_url', 'image_type')
                """))
                existing_columns = [row[0] for row in result]
            else:
                # SQLite: consultar pragma
                result = db.session.execute(text("PRAGMA table_info(coach_community)"))
                existing_columns = [row[1] for row in result if row[1] in ['image_url', 'image_type']]
            
            # Agregar image_url si no existe
            if 'image_url' not in existing_columns:
                db.session.execute(text("ALTER TABLE coach_community ADD COLUMN image_url TEXT"))
                db.session.commit()
                logger.info("✅ MIGRACIÓN: Campo 'image_url' agregado en coach_community")
            else:
                logger.info("ℹ️ MIGRACIÓN: Campo 'image_url' ya existe en coach_community")
            
            # Agregar image_type si no existe
            if 'image_type' not in existing_columns:
                db.session.execute(text("ALTER TABLE coach_community ADD COLUMN image_type VARCHAR(20) DEFAULT 'catalog'"))
                db.session.commit()
                logger.info("✅ MIGRACIÓN: Campo 'image_type' agregado en coach_community")
            else:
                logger.info("ℹ️ MIGRACIÓN: Campo 'image_type' ya existe en coach_community")
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ MIGRACIÓN: Error en migración de coach_community: {e}", exc_info=True)
        
        logger.info("✅ MIGRACIONES: Completadas exitosamente")
        return True
        
    except Exception as e:
        logger.error(f"❌ MIGRACIONES: Error ejecutando migraciones: {e}")
        db.session.rollback()
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

        # Assessment 6: Preparación para crecer 2026 - Con transacciones individuales
        try:
            if not Assessment.query.filter_by(title="Preparación para crecer 2026").first():
                growth_assessment = Assessment(
                    title="Preparación para crecer 2026",
                    description="Evaluación para determinar qué tan preparado está tu negocio para crecer de manera sostenible en 2026",
                    is_active=True
                )
                db.session.add(growth_assessment)
                db.session.flush()
                growth_id = growth_assessment.id
                logger.info(f"✅ ASSESSMENTS: Assessment Preparación para crecer 2026 creado con ID: {growth_id}")

                # Preguntas para Preparación para crecer 2026 (escala 1-3)
                growth_questions = [
                    "¿Qué tanto depende tu negocio de ti para funcionar día a día?",
                    "¿Tu empresa tiene roles y procesos definidos?",
                    "¿Cuántas horas al día dedicas a la operación?",
                    "¿Qué tan confiable y actualizada es tu información financiera?",
                    "¿Cómo te sientes respecto al crecimiento en 2026?",
                    "¿Cómo te sientes en tu rol actual?",
                    "Si sigues igual un año más, ¿cómo te sentirías?"
                ]

                # Dimensiones para Preparación para crecer 2026
                growth_dimensions = [
                    "Delegación", "Estructura organizacional", "Gestión del tiempo del dueño",
                    "Finanzas", "Crecimiento estratégico", "Bienestar personal", "Visión a futuro"
                ]

                for i, text in enumerate(growth_questions, 1):
                    question = Question(
                        assessment_id=growth_id,
                        text=text,
                        question_type='likert_3_scale',  # Nueva escala de 3 puntos
                        order=i,
                        dimension=growth_dimensions[i-1]
                    )
                    db.session.add(question)
                
                db.session.commit()
                logger.info("✅ ASSESSMENTS: Preguntas de Preparación para crecer 2026 creadas")
            else:
                logger.info("ℹ️ ASSESSMENTS: Assessment Preparación para crecer 2026 ya existe")
        except Exception as growth_error:
            logger.error(f"❌ ASSESSMENTS: Error creando Preparación para crecer 2026: {growth_error}")
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
        'platform_admin': '/admin/dashboard-alpine',
        'coach': '/coach-feed',
        'coachee': '/coachee-feed'  # Feed principal del coachee
    }
    return urls.get(role, '/coachee-feed')

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
        'coach_id': user.coach_id,
        'avatar_url': user.avatar_url
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
    dimension_totals = {}  # Para guardar totales brutos
    
    for dimension, responses_list in dimension_responses.items():
        if responses_list:
            # Calcular porcentaje para esta dimensión
            dimension_total = sum(responses_list)
            dimension_totals[dimension] = dimension_total  # Guardar total bruto
            max_possible = len(responses_list) * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
            logger.info(f"🎯 CALCULATE_DISC_SCORE: {dimension} = {dimension_total}/{max_possible} = {dimension_percentage}%")
        else:
            dimensional_scores[dimension] = 0
            dimension_totals[dimension] = 0
            logger.info(f"🎯 CALCULATE_DISC_SCORE: {dimension} = 0 (no responses found)")
    
    # Determinar estilo predominante
    if dimensional_scores:
        predominant_style = max(dimensional_scores, key=dimensional_scores.get)
        max_score = dimensional_scores[predominant_style]
        
        # Calcular puntuación general como suma de todas las respuestas (no promediar porcentajes)
        overall_score = sum(dimension_totals.values())
        
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
        
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Final result - Score: {overall_score}, Style: {predominant_style}")
        logger.info(f"🎯 CALCULATE_DISC_SCORE: Dimensional scores: {dimensional_scores}")
        
        return overall_score, result_text, dimensional_scores
    
    return 0, "No se pudieron calcular las puntuaciones DISC", {}


def calculate_disc_score_legacy(response_dict, disc_dimensions):
    """Función legacy para compatibilidad hacia atrás"""
    dimensional_scores = {}
    dimension_totals = {}  # Para guardar totales brutos
    
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
            # Guardar total bruto y calcular porcentaje para análisis
            dimension_totals[dimension] = dimension_total
            max_possible = dimension_count * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
            logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: {dimension} = {dimension_total}/{max_possible} = {dimension_percentage}%")
        else:
            dimensional_scores[dimension] = 0
            dimension_totals[dimension] = 0
            logger.info(f"🎯 CALCULATE_DISC_SCORE_LEGACY: {dimension} = 0 (no responses found)")
    
    # Determinar estilo predominante
    if dimensional_scores:
        predominant_style = max(dimensional_scores, key=dimensional_scores.get)
        overall_score = sum(dimension_totals.values())  # Suma de totales brutos, no promedio de porcentajes
        
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
    dimension_totals = {}  # Para guardar totales brutos
    
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
            # Guardar total bruto y calcular porcentaje para análisis
            dimension_totals[dimension] = dimension_total
            max_possible = dimension_count * LIKERT_SCALE_MAX
            dimension_percentage = (dimension_total / max_possible) * 100
            dimensional_scores[dimension] = round(dimension_percentage, 1)
            logger.info(f"🎯 CALCULATE_EQ_SCORE: {dimension} = {dimension_total}/{max_possible} = {dimension_percentage}%")
        else:
            dimensional_scores[dimension] = 0
            dimension_totals[dimension] = 0
            logger.info(f"🎯 CALCULATE_EQ_SCORE: {dimension} = 0 (no responses found)")

    # Calcular puntuación general como suma de todas las respuestas (no promediar porcentajes)
    if dimensional_scores:
        overall_score = sum(dimension_totals.values())
        
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

        logger.info(f"🎯 CALCULATE_EQ_SCORE: Final result - Score: {overall_score}, Level: {level}")
        logger.info(f"🎯 CALCULATE_EQ_SCORE: Dimensional scores: {dimensional_scores}")
        
        return overall_score, result_text, dimensional_scores
    
    return 0, "No se pudieron calcular las puntuaciones de Inteligencia Emocional", {}


def calculate_leadership_score(responses):
    """Calcula puntuación de Liderazgo basada en respuestas y dimensiones"""
    logger.info(f"🎯 CALCULATE_LEADERSHIP_SCORE: Starting with {len(responses) if responses else 0} responses")
    
    if not responses:
        return 0, "Sin respuestas disponibles", None

    # Manejar tanto formato lista como diccionario
    if isinstance(responses, list):
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
    else:
        response_dict = responses
    
    # Obtener preguntas de liderazgo dinámicamente desde la base de datos
    try:
        questions = Question.query.filter_by(assessment_id=4).order_by(Question.order).all()
        dimension_responses = {}
        dimension_totals = {}
        
        for question in questions:
            dimension = question.dimension if question.dimension else 'General'
            question_id_str = str(question.id)
            
            if question_id_str in response_dict:
                if dimension not in dimension_responses:
                    dimension_responses[dimension] = []
                    dimension_totals[dimension] = 0
                
                response_value = int(response_dict[question_id_str])
                dimension_responses[dimension].append(response_value)
                dimension_totals[dimension] += response_value
        
        # Calcular score total como suma de todas las respuestas
        overall_score = sum(dimension_totals.values())
        
        # Calcular porcentajes por dimensión para el análisis
        dimensional_scores = {}
        for dimension, total in dimension_totals.items():
            count = len(dimension_responses[dimension])
            if count > 0:
                max_possible = count * LIKERT_SCALE_MAX
                percentage = (total / max_possible) * 100
                dimensional_scores[dimension] = round(percentage, 1)
        
        # Clasificar nivel de liderazgo basado en porcentaje general
        num_questions = len(response_dict)
        max_possible_total = num_questions * LIKERT_SCALE_MAX
        percentage = (overall_score / max_possible_total) * 100
        
        if percentage >= 80:
            level = "Liderazgo excepcional"
            text = "Demuestras habilidades de liderazgo excepcionales en todas las áreas clave."
        elif percentage >= 60:
            level = "Buen liderazgo"
            text = "Tienes sólidas habilidades de liderazgo con oportunidades de crecimiento."
        elif percentage >= 40:
            level = "Liderazgo en desarrollo"
            text = "Muestras potencial de liderazgo con áreas importantes por desarrollar."
        else:
            level = "Liderazgo inicial"
            text = "Estás en las etapas iniciales del desarrollo de habilidades de liderazgo."
        
        result_text = f"{level}: {text}"
        
        logger.info(f"🎯 CALCULATE_LEADERSHIP_SCORE: Score={overall_score}, Level={level}")
        return overall_score, result_text, dimensional_scores
        
    except Exception as e:
        logger.error(f"🎯 CALCULATE_LEADERSHIP_SCORE: Error: {e}")
        return 0, "Error al calcular puntuación de liderazgo", {}


def calculate_teamwork_score(responses):
    """Calcula puntuación de Trabajo en Equipo basada en respuestas y dimensiones"""
    logger.info(f"🎯 CALCULATE_TEAMWORK_SCORE: Starting with {len(responses) if responses else 0} responses")
    
    if not responses:
        return 0, "Sin respuestas disponibles", None

    # Manejar tanto formato lista como diccionario
    if isinstance(responses, list):
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
    else:
        response_dict = responses
    
    # Obtener preguntas de trabajo en equipo dinámicamente desde la base de datos
    try:
        questions = Question.query.filter_by(assessment_id=5).order_by(Question.order).all()
        dimension_responses = {}
        dimension_totals = {}
        
        for question in questions:
            dimension = question.dimension if question.dimension else 'General'
            question_id_str = str(question.id)
            
            if question_id_str in response_dict:
                if dimension not in dimension_responses:
                    dimension_responses[dimension] = []
                    dimension_totals[dimension] = 0
                
                response_value = int(response_dict[question_id_str])
                dimension_responses[dimension].append(response_value)
                dimension_totals[dimension] += response_value
        
        # Calcular score total como suma de todas las respuestas
        overall_score = sum(dimension_totals.values())
        
        # Calcular porcentajes por dimensión para el análisis
        dimensional_scores = {}
        for dimension, total in dimension_totals.items():
            count = len(dimension_responses[dimension])
            if count > 0:
                max_possible = count * LIKERT_SCALE_MAX
                percentage = (total / max_possible) * 100
                dimensional_scores[dimension] = round(percentage, 1)
        
        # Clasificar nivel de trabajo en equipo basado en porcentaje general
        num_questions = len(response_dict)
        max_possible_total = num_questions * LIKERT_SCALE_MAX
        percentage = (overall_score / max_possible_total) * 100
        
        if percentage >= 80:
            level = "Excelente colaborador"
            text = "Demuestras habilidades excepcionales de trabajo en equipo y colaboración."
        elif percentage >= 60:
            level = "Buen colaborador"
            text = "Trabajas bien en equipo con oportunidades de mejorar la colaboración."
        elif percentage >= 40:
            level = "Colaborador en desarrollo"
            text = "Tienes potencial colaborativo con áreas importantes por desarrollar."
        else:
            level = "Colaborador inicial"
            text = "Estás desarrollando tus habilidades básicas de trabajo en equipo."
        
        result_text = f"{level}: {text}"
        
        logger.info(f"🎯 CALCULATE_TEAMWORK_SCORE: Score={overall_score}, Level={level}")
        return overall_score, result_text, dimensional_scores
        
    except Exception as e:
        logger.error(f"🎯 CALCULATE_TEAMWORK_SCORE: Error: {e}")
        return 0, "Error al calcular puntuación de trabajo en equipo", {}


def calculate_growth_preparation_score(responses):
    """Calcula puntuación de Preparación para crecer 2026 basada en respuestas con escala 1-3"""
    if not responses:
        return 0, "Sin respuestas disponibles", None
    
    # Manejar tanto formato lista como diccionario
    if isinstance(responses, list):
        # Si es una lista de objetos con question_id y selected_option
        response_dict = {str(r['question_id']): int(r['selected_option']) for r in responses}
    else:
        # Si es un diccionario, convertir valores a int
        response_dict = {str(k): int(v) for k, v in responses.items()}
    
    # Definir dimensiones y preguntas (IDs reales de BD: 71-77)
    dimensions_config = {
        'Delegación': {'questions': [71]},
        'Estructura organizacional': {'questions': [72]},
        'Gestión del tiempo del dueño': {'questions': [73]},
        'Finanzas': {'questions': [74]},
        'Crecimiento estratégico': {'questions': [75]},
        'Bienestar personal': {'questions': [76]},
        'Visión a futuro': {'questions': [77]}
    }
    
    dimensional_scores = {}
    respuestas_c_count = 0  # Contador de respuestas C (opción 3)
    total_score = 0  # Suma total de todas las respuestas
    
    # Calcular puntuación para cada dimensión y contar respuestas C
    for dimension, config in dimensions_config.items():
        dimension_total = 0
        dimension_count = 0
        
        for question_id in config['questions']:
            if str(question_id) in response_dict:
                response_value = response_dict[str(question_id)]
                dimension_total += response_value
                total_score += response_value  # Acumular total
                dimension_count += 1
                
                # Contar respuestas C (opción 3)
                if response_value == 3:
                    respuestas_c_count += 1
        
        if dimension_count > 0:
            # Promedio de la dimensión (escala 1-3)
            dimension_avg = dimension_total / dimension_count
            dimensional_scores[dimension] = round(dimension_avg, 2)
        else:
            dimensional_scores[dimension] = 1.0  # Valor mínimo por defecto
    
    # Sistema de semáforo basado en cantidad de respuestas C (opción 3)
    if respuestas_c_count <= 2:  # 0-2 respuestas C
        color = "Rojo"
        level = "Alta dependencia"
        text = "Tu negocio depende demasiado de ti y el desorden te está frenando. Urge tomar acción para evitar estancarte o retroceder."
        percentage_score = 25.0  # Rojo = 25%
    elif respuestas_c_count <= 4:  # 3-4 respuestas C
        color = "Amarillo"
        level = "En progreso"
        text = "Ya diste pasos, pero sigues atrapado en la operación. Este es el momento de ordenar procesos y finanzas para crecer sin agotarte."
        percentage_score = 65.0  # Amarillo = 65%
    else:  # 5-7 respuestas C
        color = "Verde"
        level = "Preparado"
        text = "Tienes buena base, ahora necesitas un plan estratégico para escalar con solidez y aprovechar al máximo el 2026."
        percentage_score = 90.0  # Verde = 90%
    
    # Formato del resultado sin CTA
    result_text = f"{level} ({color}): {text}"
    
    logger.info(f"🎯 CALCULATE_GROWTH_SCORE: Total score: {total_score}, Respuestas C: {respuestas_c_count}/7, Level: {level}")
    logger.info(f"🎯 CALCULATE_GROWTH_SCORE: Dimensional scores: {dimensional_scores}")
    
    # Retornar total_score (suma de respuestas) para consistencia con otras evaluaciones
    return total_score, result_text, dimensional_scores


def calculate_custom_assessment_score(responses, assessment_id):
    """Calcula puntuación para evaluaciones personalizadas creadas por coaches"""
    logger.info(f"🎯 CALCULATE_CUSTOM: Starting calculation for assessment {assessment_id} with {len(responses) if responses else 0} responses")
    
    if not responses:
        return 0, "Sin respuestas disponibles", None
    
    # Convertir respuestas a diccionario si es necesario
    if isinstance(responses, list):
        response_dict = {str(r['question_id']): r['selected_option'] for r in responses}
    else:
        response_dict = responses
    
    try:
        # Obtener preguntas de la evaluación
        questions = Question.query.filter_by(
            assessment_id=assessment_id,
            is_active=True
        ).order_by(Question.order).all()
        
        if not questions:
            logger.warning(f"🎯 CALCULATE_CUSTOM: No questions found for assessment {assessment_id}")
            return 0, "Evaluación sin preguntas configuradas", None
        
        logger.info(f"🎯 CALCULATE_CUSTOM: Found {len(questions)} questions")
        
        # Crear mapeo de question_id a dimensión
        question_dimensions = {}
        dimensions_set = set()
        
        for question in questions:
            question_dimensions[question.id] = question.dimension
            if question.dimension:
                dimensions_set.add(question.dimension)
        
        logger.info(f"🎯 CALCULATE_CUSTOM: Dimensions found: {dimensions_set}")
        
        # Si no hay dimensiones definidas, usar cálculo simple
        if not dimensions_set or all(d is None for d in dimensions_set):
            logger.info(f"🎯 CALCULATE_CUSTOM: No dimensions defined, using simple calculation")
            total_score = sum(int(v) for v in response_dict.values())
            max_possible = len(response_dict) * 5  # Asumiendo escala Likert 1-5
            percentage_score = (total_score / max_possible * 100) if max_possible > 0 else 0
            
            result_text = f"Puntuación obtenida: {percentage_score:.0f}%"
            
            # Agregar interpretación básica
            if percentage_score >= 80:
                result_text += " - Excelente desempeño"
            elif percentage_score >= 60:
                result_text += " - Buen desempeño"
            elif percentage_score >= 40:
                result_text += " - Desempeño moderado"
            else:
                result_text += " - Área de oportunidad"
            
            return total_score, result_text, None
        
        # Calcular scores por dimensión
        dimension_responses = {}
        
        for question_id_str, response_value in response_dict.items():
            question_id = int(question_id_str)
            if question_id in question_dimensions:
                dimension = question_dimensions[question_id]
                if dimension:  # Solo si tiene dimensión asignada
                    if dimension not in dimension_responses:
                        dimension_responses[dimension] = []
                    dimension_responses[dimension].append(int(response_value))
        
        logger.info(f"🎯 CALCULATE_CUSTOM: Dimension responses: {dimension_responses}")
        
        # Calcular puntaje promedio por dimensión (escala 0-100)
        dimensional_scores = {}
        for dimension, responses_list in dimension_responses.items():
            avg_response = sum(responses_list) / len(responses_list)
            # Convertir de escala 1-5 a 0-100
            dimension_score = ((avg_response - 1) / 4) * 100
            dimensional_scores[dimension] = round(dimension_score, 1)
        
        logger.info(f"🎯 CALCULATE_CUSTOM: Dimensional scores: {dimensional_scores}")
        
        # Calcular puntaje total
        total_score = sum(int(v) for v in response_dict.values())
        max_possible = len(response_dict) * 5
        overall_percentage = (total_score / max_possible * 100) if max_possible > 0 else 0
        
        # Generar texto de resultado con análisis por dimensión
        result_text = f"Puntuación general: {overall_percentage:.0f}%\n\n"
        result_text += "Análisis por dimensión:\n"
        
        for dimension, score in sorted(dimensional_scores.items(), key=lambda x: x[1], reverse=True):
            if score >= 75:
                level = "Excelente"
            elif score >= 60:
                level = "Bueno"
            elif score >= 40:
                level = "Moderado"
            else:
                level = "Área de mejora"
            
            result_text += f"• {dimension}: {score:.0f}% ({level})\n"
        
        logger.info(f"🎯 CALCULATE_CUSTOM: Total score: {total_score}, Overall: {overall_percentage:.0f}%")
        
        return total_score, result_text, dimensional_scores
        
    except Exception as e:
        logger.error(f"❌ CALCULATE_CUSTOM: Error calculating score: {str(e)}", exc_info=True)
        # Fallback a cálculo simple
        total_score = sum(int(v) for v in response_dict.values())
        return total_score, "Evaluación completada", None


def generate_disc_recommendations(disc_scores, overall_score):
    """Genera recomendaciones específicas para evaluaciones DISC"""
    recommendations = []
    
    # Identificar estilo dominante
    if disc_scores:
        # Verificar si hay empate en el estilo dominante
        max_score = max(disc_scores.values())
        dominant_styles = [style for style, score in disc_scores.items() if score == max_score]
        
        if len(dominant_styles) == 1:
            dominant_style = dominant_styles[0]
        else:
            # En caso de empate, usar el orden de preferencia: D, I, S, C
            style_priority = ['D', 'I', 'S', 'C']
            for style in style_priority:
                if style in dominant_styles:
                    dominant_style = style
                    break
            else:
                dominant_style = 'D'  # Fallback por defecto
    else:
        dominant_style = 'D'  # Fallback si no hay scores
    
    # Recomendaciones simplificadas por estilo DISC
    style_recommendations = {
        'D': {
            'title': '🎯 Plan de Desarrollo - Estilo Dominante',
            'focus': 'Fortalece tu liderazgo desarrollando paciencia y colaboración',
            'actions': [
                'Practica escucha activa en reuniones (15 min diarios)',
                'Delega una tarea importante cada semana',
                'Da feedback constructivo sin ser autoritario'
            ]
        },
        'I': {
            'title': '🎯 Plan de Desarrollo - Estilo Influyente',
            'focus': 'Canaliza tu energía social hacia resultados concretos',
            'actions': [
                'Usa un planificador digital para seguir tareas',
                'Dedica 30 min diarios a trabajo detallado',
                'Confirma compromisos por escrito'
            ]
        },
        'S': {
            'title': '🎯 Plan de Desarrollo - Estilo Estable',
            'focus': 'Aumenta tu confianza para liderar el cambio',
            'actions': [
                'Comparte una idea nueva cada semana',
                'Lidera un proyecto pequeño este mes',
                'Practica hablar primero en reuniones'
            ]
        },
        'C': {
            'title': '🎯 Plan de Desarrollo - Estilo Concienzudo',
            'focus': 'Equilibra tu precisión con flexibilidad y velocidad',
            'actions': [
                'Toma decisiones rápidas en asuntos menores',
                'Limita el tiempo de análisis a 80% de lo usual',
                'Inicia conversaciones informales con colegas'
            ]
        }
    }
    
    # Agregar recomendaciones del estilo dominante
    if dominant_style in style_recommendations:
        style_data = style_recommendations[dominant_style]
        recommendations.extend([
            f"**{style_data['title']}**",
            "",
            f"🎯 **Enfoque Principal:** {style_data['focus']}",
            "",
            "**Acciones Específicas (próximos 30 días):**"
        ])
        for action in style_data['actions']:
            recommendations.append(f"✓ {action}")
    
    # Plan de acción simplificado por nivel
    recommendations.extend([
        "",
        "**🚀 Próximos Pasos:**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Semana 1-2:** Elige 1 acción específica y practícala diariamente",
            "• **Semana 3-4:** Solicita feedback de un colega de confianza",
            "• **Meta:** Mentorear a alguien con estilo diferente al tuyo"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• **Semana 1-2:** Identifica tu mayor debilidad del estilo",
            "• **Semana 3-4:** Practica 2 acciones específicas",
            "• **Meta:** Mejora una interacción difícil que tengas"
        ])
    else:
        recommendations.extend([
            "• **Semana 1-2:** Observa cómo otros manejan situaciones similares",
            "• **Semana 3-4:** Practica 1 nueva habilidad de comunicación",
            "• **Meta:** Busca un mentor o coach para desarrollo personalizado"
        ])
    
    return recommendations

def generate_emotional_intelligence_recommendations(ei_scores, overall_score):
    """Genera recomendaciones específicas para Inteligencia Emocional"""
    recommendations = []
    
    # Mapeo de dimensiones IE simplificado
    dimension_names = {
        'autoconciencia': '🧠 Autoconciencia',
        'autorregulacion': '⚖️ Autorregulación',
        'automotivacion': '🎯 Automotivación',
        'empatia': '❤️ Empatía',
        'habilidades_sociales': '🤝 Habilidades Sociales'
    }
    
    # Identificar las 2 áreas más débiles (< 65%)
    development_areas = sorted(
        [(dim, score) for dim, score in ei_scores.items() if score < 65],
        key=lambda x: x[1]
    )[:2]
    
    # Recomendaciones específicas y concisas por dimensión
    dimension_actions = {
        'autoconciencia': [
            'Mindfulness 5 min al día',
            'Diario emocional semanal',
            'Pausa antes de reaccionar'
        ],
        'autorregulacion': [
            'Respiración profunda (técnica 4-7-8)',
            'Identifica tus disparadores',
            'Pausa de 6 segundos antes de responder'
        ],
        'automotivacion': [
            'Metas SMART semanales',
            'Celebra pequeños logros',
            'Visualización positiva diaria'
        ],
        'empatia': [
            'Escucha sin juzgar ni aconsejar',
            'Observa lenguaje corporal',
            'Pregunta "¿cómo te sientes?"'
        ],
        'habilidades_sociales': [
            'Inicia 1 conversación nueva al día',
            'Practica comunicación asertiva',
            'Resuelve conflictos con calma'
        ]
    }
    
    # Plan de desarrollo enfocado
    recommendations.extend([
        "**🎯 Plan de Desarrollo en Inteligencia Emocional**",
        "",
        "**Áreas Prioritarias de Desarrollo:**"
    ])
    
    # Agregar las 2 áreas más débiles
    for dimension, score in development_areas:
        dimension_name = dimension_names.get(dimension, dimension)
        actions = dimension_actions.get(dimension, [])
        
        recommendations.extend([
            f"**{dimension_name}** (Puntuación: {score}%)",
            "Acciones inmediatas:"
        ])
        for action in actions:
            recommendations.append(f"✓ {action}")
        recommendations.append("")
    
    # Plan estructurado simplificado por nivel
    recommendations.extend([
        "**🚀 Plan de Acción (próximas 4 semanas):**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Semana 1-2:** Enfócate en mentorear a otros",
            "• **Semana 3-4:** Lidera una iniciativa de bienestar emocional",
            "• **Meta:** Certificación en coaching emocional"
        ])
    elif overall_score >= 65:
        recommendations.extend([
            "• **Semana 1-2:** Practica diariamente 1 habilidad específica",
            "• **Semana 3-4:** Solicita feedback 360° sobre tu IE",
            "• **Meta:** Considera un coach especializado"
        ])
    else:
        recommendations.extend([
            "• **Semana 1-2:** 15 min diarios de autoconciencia",
            "• **Semana 3-4:** Lee 1 libro de inteligencia emocional",
            "• **Meta:** Practica 1 habilidad nueva cada semana"
        ])
    
    return recommendations

def generate_assertiveness_recommendations(assertiveness_scores, overall_score):
    """Genera recomendaciones específicas para Asertividad"""
    recommendations = []
    
    # Mapeo de dimensiones de asertividad simplificado
    dimension_names = {
        'comunicacion': '💬 Comunicación',
        'derechos': '🛡️ Defensa de Derechos',
        'opiniones': '💭 Expresión de Opiniones',
        'conflictos': '⚡ Manejo de Conflictos',
        'autoconfianza': '💪 Autoconfianza'
    }
    
    # Identificar las 2 dimensiones más débiles
    weak_dimensions = sorted(
        [(dim, score) for dim, score in assertiveness_scores.items() if score < 60],
        key=lambda x: x[1]
    )[:2]
    
    # Recomendaciones específicas y concisas
    dimension_actions = {
        'comunicacion': [
            'Mantén contacto visual al hablar',
            'Usa tono firme pero respetuoso',
            'Practica comunicación no violenta'
        ],
        'derechos': [
            'Practica decir "no" sin excusas',
            'Establece límites claros',
            'Reconoce tu valor personal'
        ],
        'opiniones': [
            'Participa activamente en reuniones',
            'Expresa desacuerdo constructivamente',
            'Prepara argumentos antes de hablar'
        ],
        'conflictos': [
            'Mantén la calma bajo presión',
            'Enfócate en problemas, no personas',
            'Usa técnicas de negociación ganar-ganar'
        ],
        'autoconfianza': [
            'Celebra logros diarios',
            'Usa autoafirmaciones positivas',
            'Desafía pensamientos negativos'
        ]
    }
    
    # Plan de desarrollo enfocado
    recommendations.extend([
        "**🎯 Plan de Desarrollo en Asertividad**",
        "",
        "**Áreas Prioritarias:**"
    ])
    
    # Agregar las 2 dimensiones más débiles
    for dimension, score in weak_dimensions:
        dimension_name = dimension_names.get(dimension, dimension)
        actions = dimension_actions.get(dimension, [])
        
        recommendations.extend([
            f"**{dimension_name}** (Puntuación: {score}%)",
            "Acciones específicas:"
        ])
        for action in actions:
            recommendations.append(f"✓ {action}")
        recommendations.append("")
    
    # Plan de desarrollo simplificado por nivel
    recommendations.extend([
        "**🚀 Plan de Acción (próximas 4 semanas):**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Semana 1-2:** Mentoriza a otros en comunicación asertiva",
            "• **Semana 3-4:** Lidera situaciones complejas como ejemplo",
            "• **Meta:** Busca roles que requieran alta asertividad"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• **Semana 1-2:** Practica en situaciones desafiantes",
            "• **Semana 3-4:** Solicita feedback sobre tu comunicación",
            "• **Meta:** Toma un curso avanzado de asertividad"
        ])
    else:
        recommendations.extend([
            "• **Semana 1-2:** Comienza con situaciones simples",
            "• **Semana 3-4:** Practica técnicas básicas diariamente",
            "• **Meta:** Considera trabajar con un coach"
        ])
    
    return recommendations

def generate_leadership_recommendations(leadership_scores, overall_score):
    """Genera recomendaciones específicas para Liderazgo"""
    recommendations = []
    
    # Plan de desarrollo simplificado para liderazgo
    recommendations.extend([
        "**🎯 Plan de Desarrollo de Liderazgo**",
        "",
        "**Competencias Prioritarias:**",
        "✓ Comunicación inspiradora y visión clara",
        "✓ Desarrollo y empoderamiento de equipos",
        "✓ Toma de decisiones efectiva",
        "",
        "**🚀 Plan de Acción (próximas 4 semanas):**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Semana 1-2:** Lidera una iniciativa de transformación",
            "• **Semana 3-4:** Mentoriza a un futuro líder",
            "• **Meta:** Busca proyectos complejos para liderar"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• **Semana 1-2:** Lidera un proyecto multifuncional",
            "• **Semana 3-4:** Practica delegación efectiva",
            "• **Meta:** Solicita feedback 360° sobre tu liderazgo"
        ])
    else:
        recommendations.extend([
            "• **Semana 1-2:** Lidera un equipo pequeño",
            "• **Semana 3-4:** Observa y aprende de líderes exitosos",
            "• **Meta:** Toma un curso de desarrollo de liderazgo"
        ])
    
    return recommendations

def generate_teamwork_recommendations(teamwork_scores, overall_score):
    """Genera recomendaciones específicas para Trabajo en Equipo"""
    recommendations = []
    
    # Plan de desarrollo simplificado para trabajo en equipo
    recommendations.extend([
        "**🎯 Plan de Desarrollo de Trabajo en Equipo**",
        "",
        "**Habilidades Colaborativas Clave:**",
        "✓ Comunicación efectiva en grupos",
        "✓ Resolución colaborativa de problemas",
        "✓ Apoyo y desarrollo de compañeros",
        "",
        "**🚀 Plan de Acción (próximas 4 semanas):**"
    ])
    
    if overall_score >= 80:
        recommendations.extend([
            "• **Semana 1-2:** Facilita un workshop colaborativo",
            "• **Semana 3-4:** Mentoriza a nuevos miembros del equipo",
            "• **Meta:** Lidera iniciativas de cultura colaborativa"
        ])
    elif overall_score >= 60:
        recommendations.extend([
            "• **Semana 1-2:** Participa activamente en proyectos grupales",
            "• **Semana 3-4:** Practica facilitación en reuniones",
            "• **Meta:** Aprende técnicas de construcción de consenso"
        ])
    else:
        recommendations.extend([
            "• **Semana 1-2:** Participa más en actividades grupales",
            "• **Semana 3-4:** Observa dinámicas de equipos exitosos",
            "• **Meta:** Busca oportunidades de colaboración en proyectos pequeños"
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
        'available_endpoints': ['/coachee-dashboard', '/coach-dashboard', '/admin/dashboard-alpine']
    })

@app.route('/health')
def health_check():
    """Health check endpoint para Railway y monitoreo"""
    health_status = {
        'status': 'healthy',
        'database': 'unknown',
        'environment': os.environ.get('FLASK_ENV', 'unknown'),
        'timestamp': datetime.now(SANTIAGO_TZ).isoformat()
    }
    
    try:
        # Verificar conexión a base de datos
        db.session.execute(text("SELECT 1"))
        health_status['database'] = 'connected'
        
        # Ejecutar migraciones necesarias ANTES de crear tablas
        migrations_applied = []
        try:
            # Lista de migraciones de columnas faltantes en la tabla user
            user_migrations = [
                ("original_password", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS original_password VARCHAR(120)"),
                ("avatar_url", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500)"),
                ("coach_notes", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS coach_notes TEXT"),
                ("last_login", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS last_login TIMESTAMP"),
            ]
            
            for column_name, migration_sql in user_migrations:
                try:
                    db.session.execute(text(migration_sql))
                    db.session.commit()
                    migrations_applied.append(column_name)
                    logger.info(f"✅ HEALTH: Migración {column_name} aplicada")
                except Exception as migration_error:
                    db.session.rollback()
                    logger.warning(f"⚠️ HEALTH: Migración {column_name}: {migration_error}")
            
            if migrations_applied:
                health_status['migrations_applied'] = migrations_applied
                logger.info(f"✅ HEALTH: Migraciones aplicadas: {migrations_applied}")
            else:
                health_status['migrations_applied'] = 'none_needed'
                
        except Exception as migration_error:
            logger.warning(f"⚠️ HEALTH: Error en migraciones: {migration_error}")
            health_status['migrations'] = 'error'
            health_status['migration_error'] = str(migration_error)
        
        # NO crear tablas incondicionalmente - puede sobrescribir esquema
        # try:
        #     db.create_all()
        #     health_status['tables'] = 'ready'
        # except Exception as table_error:
        #     logger.warning(f"⚠️ HEALTH: Error creando tablas: {table_error}")
        #     health_status['tables'] = 'error'
        health_status['tables'] = 'skipped'  # No recrear tablas
        
        # Lazy initialization de datos en primer health check
        if not hasattr(app, '_data_initialized'):
            try:
                # Verificar si hay usuarios
                user_count = User.query.count()
                if user_count == 0:
                    logger.info("🔧 HEALTH: Ejecutando inicialización de datos...")
                    auto_initialize_database()
                    app._data_initialized = True
                    health_status['initialization'] = 'completed'
                    logger.info("✅ HEALTH: Datos inicializados")
                else:
                    app._data_initialized = True
                    health_status['initialization'] = 'already_done'
                    health_status['users'] = user_count
                    logger.info(f"✅ HEALTH: {user_count} usuarios encontrados")
            except Exception as init_error:
                logger.warning(f"⚠️ HEALTH: Error en lazy init: {init_error}")
                health_status['initialization'] = 'error'
                health_status['init_error'] = str(init_error)
        else:
            health_status['initialization'] = 'previously_completed'
            
    except Exception as e:
        logger.error(f"❌ HEALTH: Error en health check: {e}")
        health_status['status'] = 'unhealthy'
        health_status['database'] = 'error'
        health_status['error'] = str(e)
    
    return jsonify(health_status)

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

@app.route('/invite/<token>')
def invitation_landing(token):
    """Página de aterrizaje para invitaciones con token único"""
    try:
        logger.info(f"🔗 INVITE: Access attempt with token: {token[:10]}...")
        
        # Buscar invitación por token
        invitation = Invitation.query.filter_by(token=token).first()
        
        if not invitation:
            logger.warning(f"❌ INVITE: Invalid token: {token[:10]}...")
            flash('Invitación inválida o no encontrada', 'error')
            return redirect(url_for('participant_access'))
        
        # Verificar si ya fue usada
        # Temporal: status comentado hasta migración en Railway
        if invitation.is_used:  # or invitation.status == 'accepted':
            logger.info(f"ℹ️ INVITE: Token already used for {invitation.email}")
            flash('Esta invitación ya fue utilizada. Por favor inicia sesión normalmente.', 'info')
            return redirect(url_for('participant_access'))
        
        # Verificar si expiró
        if invitation.expires_at < datetime.utcnow():
            logger.warning(f"⏰ INVITE: Expired token for {invitation.email}")
            flash('Esta invitación ha expirado. Contacta a tu coach.', 'warning')
            return redirect(url_for('participant_access'))
        
        # Buscar coachee
        coachee = User.query.get(invitation.coachee_id)
        if not coachee:
            logger.error(f"❌ INVITE: Coachee not found for invitation {invitation.id}")
            flash('Error: Usuario no encontrado', 'error')
            return redirect(url_for('participant_access'))
        
        # Buscar assessment si está asignado
        # Temporal: assessment_id comentado hasta migración en Railway
        assessment_title = None
        # if invitation.assessment_id:
        #     assessment = Assessment.query.get(invitation.assessment_id)
        #     if assessment:
        #         assessment_title = assessment.title
        
        logger.info(f"✅ INVITE: Valid invitation for {coachee.full_name} ({coachee.email})")
        
        # Renderizar página de bienvenida con datos pre-llenados
        return render_template('invitation_welcome.html',
                             token=token,
                             username=coachee.username,
                             full_name=coachee.full_name,
                             email=coachee.email,
                             assessment_title=assessment_title,
                             coach_name=invitation.coach.full_name if invitation.coach else 'Tu coach')
    
    except Exception as e:
        logger.error(f"❌ INVITE: Error processing invitation: {str(e)}")
        flash('Error al procesar la invitación', 'error')
        return redirect(url_for('participant_access'))

@app.route('/dashboard_selection')
@app.route('/dashboard-selection')
def dashboard_selection():
    return render_template('dashboard_selection.html')



# API Routes principales
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    try:
        data = request.get_json()
        
        # Validar y sanitizar inputs
        valid, result = validate_and_sanitize_login_input(data)
        if not valid:
            logger.warning(f"Login attempt with invalid input from {request.remote_addr}: {result}")
            return jsonify({'error': result}), 400
        
        username = result['username_or_email']
        password = result['password']
        dashboard_type = data.get('dashboard_type', 'auto')  # 'coach', 'coachee', 'auto'
        
        logger.info(f"🔐 LOGIN: Attempt for username/email: {username}, dashboard_type: {dashboard_type}")
        
        user = User.query.filter((User.username == username) | (User.email == username)).first()  # type: ignore
        
        if not user:
            logger.warning(f"❌ LOGIN: User not found for username/email: {username}")
        else:
            logger.info(f"✅ LOGIN: User found - ID: {user.id}, Username: {user.username}, Role: {user.role}, Active: {user.is_active}")
        
        # Forzar recarga desde BD para evitar caché desactualizado
        if user:
            db.session.refresh(user)
        
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
            
            # Registrar login exitoso en auditoría
            log_successful_login(user)
            
            logger.info(f"Successful login for user {user.username} (ID: {user.id}, Role: {user.role}, Dashboard: {dashboard_type}) from {request.remote_addr}")
            
            return jsonify({
                'success': True,
                'user': create_user_response(user),
                'redirect': get_dashboard_url(user.role)
            }), 200
        else:
            # Registrar login fallido en auditoría
            log_failed_login(username, 'Invalid credentials or inactive account')
            
            # Verificar si hay ataque sostenido de fuerza bruta
            if check_failed_login_threshold(request.remote_addr):
                send_security_alert(
                    event_type='sustained_attack',
                    details={
                        'ip_address': request.remote_addr,
                        'username': username,
                        'user_role': 'unknown',
                        'attempts': '>5',
                        'time_window': '10 minutes',
                        'description': f'Ataque de fuerza bruta detectado: >5 intentos fallidos de login en 10 minutos desde IP {request.remote_addr}'
                    }
                )
            
            logger.warning(f"Failed login attempt for username '{username}' from {request.remote_addr}")
            return jsonify({'error': 'Credenciales inválidas o cuenta desactivada'}), 401
            
    except Exception as e:
        logger.error(f"Error in api_login: {str(e)}")
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/invite-login', methods=['POST'])
@limiter.limit("5 per minute")
def api_invite_login():
    """Login especial para invitaciones con token - redirige directo a evaluación"""
    try:
        data = request.get_json()
        
        # Sanitizar token
        token = sanitize_string(data.get('token'), 100)
        
        # Validar contraseña
        password = data.get('password')
        valid, result = validate_password(password)
        if not valid:
            logger.warning(f"Invite-login attempt with invalid password from {request.remote_addr}")
            return jsonify({'error': result}), 400
        password = result
        
        logger.info(f"🔐 INVITE-LOGIN: Login attempt with token: {token[:10] if token else 'None'}...")
        
        if not token or not password:
            logger.warning("❌ INVITE-LOGIN: Missing token or password")
            return jsonify({'success': False, 'error': 'Token y contraseña requeridos'}), 400
        
        # Validar invitación
        invitation = Invitation.query.filter_by(token=token).first()
        
        if not invitation:
            logger.warning(f"❌ INVITE-LOGIN: Invalid token: {token[:10]}...")
            return jsonify({'success': False, 'error': 'Token de invitación inválido'}), 400
        
        # Temporal: status comentado hasta migración en Railway
        if invitation.is_used:  # or invitation.status == 'accepted':
            logger.info(f"ℹ️ INVITE-LOGIN: Token already used for {invitation.email}")
            return jsonify({'success': False, 'error': 'Esta invitación ya fue utilizada', 'redirect': '/participant-access'}), 400
        
        if invitation.expires_at < datetime.utcnow():
            logger.warning(f"⏰ INVITE-LOGIN: Expired token for {invitation.email}")
            return jsonify({'success': False, 'error': 'Esta invitación ha expirado'}), 400
        
        # Validar password del coachee
        coachee = User.query.get(invitation.coachee_id)
        
        if not coachee:
            logger.error(f"❌ INVITE-LOGIN: Coachee not found for invitation {invitation.id}")
            return jsonify({'success': False, 'error': 'Usuario no encontrado'}), 404
        
        if not coachee.check_password(password):
            logger.warning(f"❌ INVITE-LOGIN: Invalid password for {coachee.username}")
            
            # Registrar login fallido en auditoría
            log_failed_login(coachee.username, 'Invalid password via invitation')
            
            # Verificar si hay ataque sostenido de fuerza bruta
            if check_failed_login_threshold(request.remote_addr):
                send_security_alert(
                    event_type='sustained_attack',
                    details={
                        'ip_address': request.remote_addr,
                        'username': coachee.username,
                        'user_role': 'coachee',
                        'attempts': '>5',
                        'time_window': '10 minutes',
                        'description': f'Ataque de fuerza bruta detectado en login por invitación: >5 intentos fallidos en 10 minutos desde IP {request.remote_addr}'
                    }
                )
            
            return jsonify({'success': False, 'error': 'Contraseña incorrecta'}), 401
        
        # Crear sesión de coachee (sin limpiar otras sesiones)
        session['coachee_user_id'] = coachee.id
        session['user_id'] = coachee.id
        session['username'] = coachee.username
        session['role'] = 'coachee'
        session['first_login'] = True  # Marcar como primera vez
        # Temporal: assessment_id comentado hasta migración en Railway
        session['target_assessment_id'] = None  # invitation.assessment_id
        session.permanent = True
        
        # Actualizar last_login
        coachee.last_login = datetime.utcnow()
        
        # Marcar invitación como aceptada
        # Temporal: status y accepted_at comentados hasta migración en Railway
        # invitation.status = 'accepted'
        invitation.is_used = True
        invitation.used_at = datetime.utcnow()
        # invitation.accepted_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"✅ INVITE-LOGIN: Successful login for {coachee.full_name} via invitation")
        # Temporal: assessment_id comentado hasta migración en Railway
        # logger.info(f"🎯 INVITE-LOGIN: Will redirect to assessment ID: {invitation.assessment_id}")
        
        # Determinar URL de redirección
        # Temporal: assessment_id comentado hasta migración en Railway
        # if invitation.assessment_id:
        #     redirect_url = f'/coachee-dashboard?auto_start={invitation.assessment_id}'
        # else:
        if True:  # Siempre redirigir al feed
            # Si no hay evaluación asignada, ir al feed
            redirect_url = '/coachee-feed'
        
        return jsonify({
            'success': True,
            'message': f'Bienvenido {coachee.full_name}',
            'redirect': redirect_url,
            'user': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'role': 'coachee'
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ INVITE-LOGIN: Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Error en login: {str(e)}'}), 500

@app.route('/logout')
def logout_page():
    user_info = "unknown user"
    user_type = None
    
    # Detectar qué tipo de usuario está haciendo logout
    if 'coach_user_id' in session:
        user_type = 'coach'
        coach_id = session['coach_user_id']
        user_info = f"coach (ID: {coach_id})"
        logger.info(f"Logout for {user_info} - preserving coachee session")
        
        # Solo cerrar sesión de coach
        session.pop('coach_user_id', None)
        
        # Solo usar logout_user() si no hay sesión de coachee
        if 'coachee_user_id' not in session:
            logout_user()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
            
    elif 'coachee_user_id' in session:
        user_type = 'coachee'
        coachee_id = session.get('coachee_user_id')
        if not coachee_id:
            return redirect(url_for('participant_access'))
        user_info = f"coachee (ID: {coachee_id})"
        logger.info(f"Logout for {user_info} - preserving coach session")
        
        # Solo cerrar sesión de coachee
        session.pop('coachee_user_id', None)
        session.pop('temp_coachee_id', None)
        
        # Solo usar logout_user() si no hay sesión de coach
        if 'coach_user_id' not in session:
            logout_user()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
    else:
        # Si no hay sesiones específicas, hacer logout completo
        if current_user.is_authenticated:
            user_info = f"user {current_user.username} (ID: {current_user.id})"
        logger.info(f"General logout for {user_info}")
        logout_user()
        session.clear()
    
    return redirect('/')

@app.route('/api/logout', methods=['POST'])
def api_logout():
    user_info = "unknown user"
    user_type = None
    
    # Detectar qué tipo de usuario está haciendo logout
    if 'coach_user_id' in session:
        user_type = 'coach'
        coach_id = session['coach_user_id']
        user_info = f"coach (ID: {coach_id})"
        logger.info(f"API logout for {user_info} - preserving coachee session")
        
        # Solo cerrar sesión de coach
        session.pop('coach_user_id', None)
        
        # Solo usar logout_user() si no hay sesión de coachee
        if 'coachee_user_id' not in session:
            logout_user()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
            
        return jsonify({'success': True, 'message': 'Sesión de coach cerrada exitosamente', 'type': 'coach'}), 200
        
    elif 'coachee_user_id' in session:
        user_type = 'coachee'
        coachee_id = session.get('coachee_user_id')
        if not coachee_id:
            return jsonify({'error': 'Sesión expirada'}), 401
        user_info = f"coachee (ID: {coachee_id})"
        logger.info(f"API logout for {user_info} - preserving coach session")
        
        # Solo cerrar sesión de coachee
        session.pop('coachee_user_id', None)
        session.pop('temp_coachee_id', None)
        
        # Solo usar logout_user() si no hay sesión de coach
        if 'coach_user_id' not in session:
            logout_user()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
            
        return jsonify({'success': True, 'message': 'Sesión de coachee cerrada exitosamente', 'type': 'coachee'}), 200
    else:
        # Si no hay sesiones específicas, hacer logout completo
        logger.info(f"General API logout for {user_info}")
        logout_user()
        # Limpiar sesiones específicas de dashboards
        session.pop('_user_id', None)
        session.pop('_fresh', None)
        session.pop('temp_coachee_id', None)
    session.pop('coachee_user_id', None)
    return jsonify({'success': True, 'message': 'Sesión cerrada exitosamente'}), 200

@app.route('/api/coach/logout', methods=['POST'])
def api_coach_logout():
    """Logout seguro para coaches con expiración forzada de cookies y limpieza completa"""
    try:
        coach_id = session.get('coach_user_id')
        coach_username = None
        
        if coach_id:
            try:
                coach_user = User.query.get(coach_id)
                if coach_user:
                    coach_username = coach_user.username
            except:
                pass
        
        logger.info(f"🔓 Coach logout initiated (ID: {coach_id}, Username: {coach_username})")
        
        # Registrar evento de seguridad
        if coach_id:
            try:
                log_security_event(
                    user_id=coach_id,
                    event_type='logout',
                    details=f'Coach {coach_username} cerró sesión',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
            except Exception as e:
                logger.error(f"Error logging security event: {str(e)}")
        
        # Solo cerrar sesión de coach, preservar coachee
        session.pop('coach_user_id', None)
        session.pop('last_activity_coach', None)
        
        # Solo usar logout_user() si no hay sesión de coachee activa
        if 'coachee_user_id' not in session:
            logout_user()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
        
        # Marcar sesión como modificada para forzar actualización
        session.modified = True
        
        # Crear respuesta con redirección
        response = make_response(jsonify({
            'success': True, 
            'message': 'Sesión de coach cerrada exitosamente',
            'redirect_url': '/coach-login'
        }), 200)
        
        # Expirar explícitamente las cookies de sesión
        response.set_cookie('session', '', expires=0, path='/', httponly=True, samesite='Lax')
        response.set_cookie('remember_token', '', expires=0, path='/', httponly=True, samesite='Lax')
        
        # Agregar headers de control de cache para prevenir acceso con botón atrás
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        logger.info(f"✅ Coach logout completed successfully (ID: {coach_id})")
        return response
        
    except Exception as e:
        logger.error(f"❌ Error during coach logout: {str(e)}")
        # En caso de error, forzar limpieza selectiva de sesión de coach
        try:
            session.pop('coach_user_id', None)
            session.pop('last_activity_coach', None)
            # Solo usar logout_user() si no hay sesión de coachee
            if 'coachee_user_id' not in session:
                logout_user()
                session.pop('_user_id', None)
                session.pop('_fresh', None)
        except:
            pass
        
        response = make_response(jsonify({
            'success': True, 
            'message': 'Sesión cerrada',
            'redirect_url': '/coach-login'
        }), 200)
        
        # Expirar cookies incluso en caso de error
        response.set_cookie('session', '', expires=0, path='/', httponly=True, samesite='Lax')
        response.set_cookie('remember_token', '', expires=0, path='/', httponly=True, samesite='Lax')
        
        return response

@app.route('/api/coachee/logout', methods=['POST'])
def api_coachee_logout():
    """Logout específico para coachees - solo cierra sesión de coachee"""
    coachee_id = session.get('coachee_user_id')
    if not coachee_id:
        return jsonify({'error': 'No hay sesión de coachee activa'}), 400
    logger.info(f"Coachee logout (ID: {coachee_id}) - preserving coach session")
    
    # Solo cerrar sesión de coachee, preservar coach
    session.pop('coachee_user_id', None)
    session.pop('temp_coachee_id', None)
    
    # Solo usar logout_user() si no hay sesión de coach activa
    if 'coach_user_id' not in session:
        logout_user()
        session.pop('_user_id', None)
        session.pop('_fresh', None)
    
    return jsonify({'success': True, 'message': 'Sesión de coachee cerrada exitosamente', 'type': 'coachee'}), 200

@app.route('/api/admin/logout', methods=['POST'])
def api_admin_logout():
    """Logout específico para administradores - cierra sesión completamente"""
    try:
        # Verificar que el usuario sea admin
        if not current_user.is_authenticated or current_user.role != 'platform_admin':
            # No hay sesión de admin, no hacer nada
            return jsonify({'error': 'No hay sesión de administrador activa'}), 400
        
        admin_id = current_user.id
        admin_username = current_user.username
        logger.info(f"Admin logout (ID: {admin_id}, username: {admin_username})")
        
        # Registrar evento de seguridad
        log_security_event(
            event_type='admin_logout',
            severity='info',
            user_id=admin_id,
            username=admin_username,
            description='Administrador cerró sesión exitosamente'
        )
        
        # Limpiar completamente la sesión de Flask-Login
        logout_user()
        
        # Limpiar solo variables de admin/flask-login (preservar coach/coachee)
        session.pop('_user_id', None)
        session.pop('_fresh', None)
        session.pop('_id', None)
        
        # Forzar regeneración de session ID (previene session fixation)
        session.modified = True
        
        # Crear respuesta con headers para expirar cookies
        response = make_response(jsonify({
            'success': True, 
            'message': 'Sesión de administrador cerrada exitosamente',
            'redirect_url': '/admin-login'
        }), 200)
        
        # Expirar explícitamente las cookies de sesión
        response.set_cookie('session', '', expires=0, path='/', httponly=True, samesite='Lax')
        response.set_cookie('remember_token', '', expires=0, path='/', httponly=True, samesite='Lax')
        
        # Agregar headers de control de cache
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Error during admin logout: {str(e)}")
        # En caso de error, forzar limpieza selectiva de sesión de admin
        try:
            logout_user()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
            session.pop('_id', None)
        except:
            pass
        
        response = make_response(jsonify({
            'success': True, 
            'message': 'Sesión cerrada',
            'redirect_url': '/admin-login'
        }), 200)
        
        # Expirar cookies incluso en caso de error
        response.set_cookie('session', '', expires=0, path='/', httponly=True, samesite='Lax')
        response.set_cookie('remember_token', '', expires=0, path='/', httponly=True, samesite='Lax')
        
        return response

# ============================================================================
# ENDPOINTS DE CAMBIO DE CONTRASEÑA
# ============================================================================

@app.route('/api/admin/profile', methods=['GET'])
@admin_required
def get_admin_profile():
    """Obtiene el perfil del administrador autenticado"""
    try:
        # Verificar sesión de administrador
        if not current_user.is_authenticated or current_user.role != 'platform_admin':
            return jsonify({
                'error': 'No hay sesión de administrador activa',
                'redirect_url': '/admin-login',
                'session_expired': True
            }), 401
        
        return jsonify({
            'success': True,
            'profile': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'full_name': current_user.full_name,
                'role': current_user.role
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting admin profile: {str(e)}")
        return jsonify({'error': 'Error al obtener el perfil'}), 500

@app.route('/api/admin/profile', methods=['PUT'])
@admin_required
def update_admin_profile():
    """Actualiza el perfil del administrador autenticado"""
    try:
        # Verificar sesión de administrador
        if not current_user.is_authenticated or current_user.role != 'platform_admin':
            return jsonify({
                'error': 'No hay sesión de administrador activa',
                'redirect_url': '/admin-login',
                'session_expired': True
            }), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        full_name = data.get('full_name', '').strip()
        email = data.get('email', '').strip()
        
        # Validar que al menos un campo esté presente
        if not full_name and not email:
            return jsonify({'error': 'Debe proporcionar al menos un campo para actualizar'}), 400
        
        # Validar nombre completo
        if full_name and len(full_name) < 3:
            return jsonify({'error': 'El nombre completo debe tener al menos 3 caracteres'}), 400
        
        # Validar email
        if email:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                return jsonify({'error': 'Email inválido'}), 400
            
            # Verificar si el email ya existe (excluyendo el usuario actual)
            existing_user = User.query.filter(
                User.email == email,
                User.id != current_user.id
            ).first()
            
            if existing_user:
                return jsonify({'error': 'Este email ya está registrado por otro usuario'}), 400
        
        # Actualizar campos
        if full_name:
            current_user.full_name = full_name
        if email:
            current_user.email = email
        
        db.session.commit()
        
        # Registrar evento de seguridad
        log_security_event(
            event_type='profile_updated',
            severity='info',
            user_id=current_user.id,
            username=current_user.username or current_user.email,
            description=f'Perfil actualizado (Admin): {current_user.username}'
        )
        
        logger.info(f"Profile updated for admin {current_user.username or current_user.email} (ID: {current_user.id})")
        return jsonify({
            'success': True,
            'message': 'Perfil actualizado correctamente',
            'profile': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'full_name': current_user.full_name,
                'role': current_user.role
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating admin profile: {str(e)}")
        return jsonify({'error': 'Error al actualizar el perfil'}), 500

@app.route('/api/admin/change-password', methods=['POST'])
@admin_required
def admin_change_password():
    """Permite a un administrador cambiar su contraseña"""
    try:
        # Verificar sesión de administrador (el rol correcto es 'platform_admin')
        if not current_user.is_authenticated or current_user.role != 'platform_admin':
            return jsonify({
                'error': 'No hay sesión de administrador activa',
                'redirect_url': '/admin-login',
                'session_expired': True
            }), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validar que todos los campos estén presentes
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        # Verificar que las contraseñas nuevas coincidan
        if new_password != confirm_password:
            return jsonify({'error': 'Las contraseñas nuevas no coinciden'}), 400
        
        # Obtener usuario administrador
        admin = current_user
        
        # Verificar contraseña actual usando el método del modelo
        if not admin.check_password(current_password):
            log_security_event(
                event_type='password_change_failed',
                severity='warning',
                user_id=admin.id,
                username=admin.username or admin.email,
                description='Intento de cambio de contraseña con contraseña actual incorrecta (Admin)'
            )
            return jsonify({'error': 'La contraseña actual es incorrecta'}), 401
        
        # ✨ NUEVO: Validar que la nueva contraseña sea diferente a la actual
        if admin.check_password(new_password):
            log_security_event(
                event_type='password_reuse_attempt',
                severity='info',
                user_id=admin.id,
                username=admin.username or admin.email,
                description='Intento de reutilizar la misma contraseña (Admin)'
            )
            return jsonify({'error': 'La nueva contraseña debe ser diferente a la contraseña actual'}), 400
        
        # Validar fortaleza de la nueva contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Actualizar contraseña usando el método del modelo
        admin.set_password(new_password)
        db.session.add(admin)  # Asegurar que SQLAlchemy detecte el cambio
        db.session.flush()     # Forzar escritura inmediata a BD
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        # Registrar cambio exitoso
        log_password_change(admin.id, 'admin', admin.username or admin.email)
        
        logger.info(f"Password changed successfully for admin {admin.username or admin.email} (ID: {admin.id})")
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in admin password change: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Error al cambiar la contraseña'}), 500

@app.route('/api/coach/change-password', methods=['POST'])
def coach_change_password():
    """Permite a un coach cambiar su contraseña"""
    try:
        # Verificar sesión de coach
        if 'coach_user_id' not in session:
            return jsonify({
                'error': 'No hay sesión de coach activa',
                'redirect_url': '/coach-login',
                'session_expired': True
            }), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validar que todos los campos estén presentes
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        # Verificar que las contraseñas nuevas coincidan
        if new_password != confirm_password:
            return jsonify({'error': 'Las contraseñas nuevas no coinciden'}), 400
        
        # Obtener coach (es un User con role='coach')
        coach_id = session['coach_user_id']
        coach = User.query.filter_by(id=coach_id, role='coach').first()
        if not coach:
            return jsonify({'error': 'Coach no encontrado'}), 404
        
        # Verificar contraseña actual
        if not coach.check_password(current_password):
            log_security_event(
                event_type='password_change_failed',
                severity='warning',
                user_id=coach.id,
                username=coach.email,
                description='Intento de cambio de contraseña con contraseña actual incorrecta (Coach)'
            )
            return jsonify({'error': 'La contraseña actual es incorrecta'}), 401
        
        # Validar fortaleza de la nueva contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Actualizar contraseña
        coach.set_password(new_password)
        db.session.add(coach)  # Asegurar que SQLAlchemy detecte el cambio
        db.session.flush()     # Forzar escritura inmediata a BD
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        # Registrar cambio exitoso
        log_password_change(coach.id, 'coach', coach.email)
        
        logger.info(f"Password changed successfully for coach {coach.email} (ID: {coach.id})")
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in coach password change: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Error al cambiar la contraseña'}), 500

@app.route('/api/coachee/change-password', methods=['POST'])
def coachee_change_password():
    """Permite a un coachee cambiar su contraseña"""
    try:
        # Verificar sesión de coachee
        if 'coachee_user_id' not in session:
            return jsonify({
                'error': 'No hay sesión de coachee activa',
                'redirect_url': '/login',
                'session_expired': True
            }), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validar que todos los campos estén presentes
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        # Verificar que las contraseñas nuevas coincidan
        if new_password != confirm_password:
            return jsonify({'error': 'Las contraseñas nuevas no coinciden'}), 400
        
        # Obtener coachee (es un User con role='coachee')
        coachee_id = session.get('coachee_user_id')
        if not coachee_id:
            return jsonify({'error': 'Sesión expirada. Por favor, inicie sesión nuevamente.', 'session_expired': True}), 401
        coachee = User.query.filter_by(id=coachee_id, role='coachee').first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado'}), 404
        
        # Verificar contraseña actual
        if not coachee.check_password(current_password):
            log_security_event(
                event_type='password_change_failed',
                severity='warning',
                user_id=coachee.id,
                username=coachee.email,
                description='Intento de cambio de contraseña con contraseña actual incorrecta (Coachee)'
            )
            return jsonify({'error': 'La contraseña actual es incorrecta'}), 401
        
        # Validar fortaleza de la nueva contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Actualizar contraseña
        coachee.set_password(new_password)
        db.session.add(coachee)  # Asegurar que SQLAlchemy detecte el cambio
        db.session.flush()     # Forzar escritura inmediata a BD
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        # Registrar cambio exitoso
        log_password_change(coachee.id, 'coachee', coachee.email)
        log_password_change(coachee.id, 'coachee', coachee.email)
        
        logger.info(f"Password changed successfully for coachee {coachee.email} (ID: {coachee.id})")
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in coachee password change: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Error al cambiar la contraseña'}), 500

# ============================================================================
# FIN DE ENDPOINTS DE CAMBIO DE CONTRASEÑA
# ============================================================================

@app.route('/api/register', methods=['POST'])
@limiter.limit("3 per hour")  # Máximo 3 solicitudes por hora por IP
def api_register():
    """
    Endpoint para solicitudes de registro de coach.
    Ahora crea una solicitud pendiente de aprobación en vez de crear el usuario directamente.
    El administrador debe aprobar la solicitud desde el dashboard de administración.
    
    Security:
    - Rate limited: 3 requests per hour per IP
    - HTML sanitization on text fields
    - Field size limits enforced
    - DNS validation of email domain
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Extraer y sanitizar datos del formulario
        from markupsafe import escape
        full_name = escape(data.get('full_name', '').strip())
        email = data.get('email', '').strip().lower()
        username = escape(data.get('username', '').strip())
        areas = data.get('areas', [])
        experiencia = escape(data.get('experiencia', '').strip())
        estilo = escape(data.get('estilo', '').strip())
        bio = escape(data.get('bio', '').strip())
        
        # Validaciones de tamaño
        if len(str(full_name)) > 200:
            return jsonify({'error': 'Nombre muy largo (máximo 200 caracteres)'}), 400
        if len(str(username)) > 80:
            return jsonify({'error': 'Usuario muy largo (máximo 80 caracteres)'}), 400
        if len(str(bio)) > 5000:
            return jsonify({'error': 'Biografía muy larga (máximo 5000 caracteres)'}), 400
        
        # Validaciones básicas
        if not all([full_name, email, username]):
            return jsonify({'error': 'Nombre, email y usuario son requeridos'}), 400
        
        # Validar formato de email con regex más estricto
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return jsonify({'error': 'Formato de email inválido'}), 400
        
        # Verificar que el dominio del email existe (DNS lookup)
        try:
            import socket
            domain = email.split('@')[1]
            socket.gethostbyname(domain)
        except (socket.gaierror, IndexError):
            logger.warning(f"⚠️ Email con dominio inválido o no existente: {email}")
            return jsonify({'error': 'El dominio del email no es válido o no existe'}), 400
        
        # Verificar si ya existe un usuario con ese email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'El email ya está registrado en el sistema'}), 409
        
        # Verificar si ya existe una solicitud pendiente con ese email
        existing_request = CoachRequest.query.filter_by(email=email, status='pending').first()
        if existing_request:
            return jsonify({'error': 'Ya existe una solicitud pendiente con este email'}), 409
        
        # Convertir áreas a JSON string si es array
        import json
        areas_json = json.dumps(areas) if isinstance(areas, list) else areas
        
        # Crear nueva solicitud de coach
        coach_request = CoachRequest(
            full_name=full_name,
            email=email,
            username=username,
            areas=areas_json,
            experiencia=experiencia,
            estilo=estilo,
            bio=bio,
            status='pending'
        )
        
        db.session.add(coach_request)
        db.session.commit()
        
        # Enviar emails de manera asíncrona para no bloquear la respuesta
        email_to_support_sent = send_coach_request_email(coach_request)
        email_to_applicant_sent = send_confirmation_email_to_applicant(coach_request)
        
        logger.info(f"✅ Nueva solicitud de coach recibida: {full_name} ({email}) - ID: {coach_request.id}")
        logger.info(f"📧 Emails enviados - Support: {email_to_support_sent}, Confirmación: {email_to_applicant_sent}")
        
        return jsonify({
            'success': True,
            'message': 'Solicitud enviada exitosamente',
            'note': 'Tu solicitud ha sido recibida. Revisa tu email para confirmar que la recibimos. Te contactaremos en 2-3 días hábiles.',
            'emails_sent': {
                'support': email_to_support_sent,
                'confirmation': email_to_applicant_sent
            }
        }), 201
        
    except Exception as e:
        logger.error(f"❌ Error procesando solicitud de coach: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Error al procesar la solicitud. Intenta nuevamente.'}), 500

# Rutas de administrador
@app.route('/admin-login')
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_admin_login():
    try:
        data = request.get_json()
        
        # Validar y sanitizar inputs
        valid, result = validate_and_sanitize_login_input(data)
        if not valid:
            logger.warning(f"Admin login attempt with invalid input from {request.remote_addr}: {result}")
            log_suspicious_activity(f'Admin login with invalid input: {result}', username=data.get('username'))
            return jsonify({'error': result}), 400
        
        username = result['username_or_email']
        password = result['password']
        
        # SEGURIDAD: Verificar bloqueo de cuenta por intentos fallidos
        is_locked, remaining_time, attempts = check_account_lockout(username)
        if is_locked:
            logger.warning(f"🔒 ADMIN ACCOUNT LOCKED: {username} - {attempts} failed attempts, {remaining_time} minutes remaining")
            log_security_event(
                event_type='login_blocked',
                severity='warning',
                username=username,
                user_role='platform_admin',
                description=f'Account locked: {attempts} failed attempts, {remaining_time} minutes remaining'
            )
            return jsonify({
                'error': f'Cuenta temporalmente bloqueada por seguridad. Intenta nuevamente en {remaining_time} minutos.',
                'locked': True,
                'remaining_minutes': remaining_time
            }), 429
        
        admin_user = User.query.filter(User.username == username, User.role == 'platform_admin').first()  # type: ignore
        
        # Forzar recarga desde BD para evitar caché desactualizado
        if admin_user:
            db.session.refresh(admin_user)
        
        if admin_user and admin_user.check_password(password) and admin_user.is_active:
            # Crear sesión de admin (sin limpiar otras sesiones)
            login_user(admin_user, remember=True)
            session.permanent = True
            admin_user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Registrar login de admin exitoso (crítico)
            log_security_event(
                event_type='login_success',
                severity='info',
                user_id=admin_user.id,
                username=admin_user.username,
                user_role='platform_admin',
                description='Admin login successful'
            )
            
            return jsonify({
                'success': True,
                'user': create_user_response(admin_user),
                'redirect_url': '/admin/dashboard-alpine'
            }), 200
        else:
            # Registrar intento fallido de admin (crítico)
            log_security_event(
                event_type='login_failed',
                severity='error',
                username=username,
                user_role='platform_admin',
                description='Admin login failed - invalid credentials'
            )
            
            # Verificar si hay ataque sostenido de fuerza bruta (crítico para admin)
            if check_failed_login_threshold(request.remote_addr):
                send_security_alert(
                    event_type='sustained_attack',
                    details={
                        'ip_address': request.remote_addr,
                        'username': username,
                        'user_role': 'platform_admin',
                        'attempts': '>5',
                        'time_window': '10 minutes',
                        'description': f'⚠️ CRÍTICO: Ataque de fuerza bruta contra cuenta ADMIN detectado: >5 intentos fallidos en 10 minutos desde IP {request.remote_addr}'
                    }
                )
            
            return jsonify({'error': 'Credenciales de administrador inválidas'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

# ==================== RECUPERACIÓN DE CONTRASEÑA ====================

def generate_reset_token():
    """Genera un token seguro para recuperación de contraseña"""
    import secrets
    return secrets.token_urlsafe(32)

def send_password_reset_email(user_email, reset_token, user_role='admin'):
    """Envía email de recuperación de contraseña usando SMTP"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        # Configuración SMTP (Gmail/Google Workspace)
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_username = os.getenv('SMTP_USERNAME', 'support@instacoach.cl')
        smtp_password = os.getenv('SMTP_PASSWORD', '')
        sender_email = os.getenv('SENDER_EMAIL', 'support@instacoach.cl')
        sender_name = os.getenv('SENDER_NAME', 'Instacoach - Soporte')
        
        # Validar que tenemos las credenciales
        if not smtp_password:
            logger.warning("SMTP_PASSWORD no configurado. Email no enviado. URL de recuperación en logs.")
            reset_url = f"{request.host_url}reset-password/{user_role}/{reset_token}"
            logger.info(f"Password reset URL for {user_email}: {reset_url}")
            return False
        
        # Construir URL de recuperación
        reset_url = f"{request.host_url}reset-password/{user_role}/{reset_token}"
        
        # Determinar nombre del rol para el email
        role_names = {
            'admin': 'Administrador',
            'coach': 'Coach',
            'coachee': 'Coachee'
        }
        role_display = role_names.get(user_role, 'Usuario')
        
        # Crear mensaje HTML
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Recuperación de Contraseña</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
            <table role="presentation" style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td align="center" style="padding: 40px 0;">
                        <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                            <!-- Header -->
                            <tr>
                                <td style="padding: 40px 40px 30px 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px 8px 0 0;">
                                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">Instacoach</h1>
                                    <p style="margin: 10px 0 0 0; color: #ffffff; font-size: 16px;">Plataforma de Evaluaciones</p>
                                </td>
                            </tr>
                            
                            <!-- Body -->
                            <tr>
                                <td style="padding: 40px;">
                                    <h2 style="margin: 0 0 20px 0; color: #333333; font-size: 24px;">Recuperación de Contraseña</h2>
                                    
                                    <p style="margin: 0 0 20px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                                        Hola,
                                    </p>
                                    
                                    <p style="margin: 0 0 20px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                                        Recibimos una solicitud para restablecer la contraseña de tu cuenta de <strong>{role_display}</strong> en Instacoach.
                                    </p>
                                    
                                    <p style="margin: 0 0 30px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                                        Haz clic en el siguiente botón para crear una nueva contraseña:
                                    </p>
                                    
                                    <!-- Button -->
                                    <table role="presentation" style="margin: 0 auto;">
                                        <tr>
                                            <td style="border-radius: 6px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                                                <a href="{reset_url}" target="_blank" style="display: inline-block; padding: 16px 40px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: bold; border-radius: 6px;">
                                                    Restablecer Contraseña
                                                </a>
                                            </td>
                                        </tr>
                                    </table>
                                    
                                    <p style="margin: 30px 0 20px 0; color: #666666; font-size: 14px; line-height: 1.6;">
                                        O copia y pega este enlace en tu navegador:
                                    </p>
                                    
                                    <p style="margin: 0 0 30px 0; padding: 15px; background-color: #f8f9fa; border-radius: 4px; color: #667eea; font-size: 14px; word-break: break-all;">
                                        {reset_url}
                                    </p>
                                    
                                    <div style="margin: 30px 0; padding: 20px; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                                        <p style="margin: 0; color: #856404; font-size: 14px; line-height: 1.6;">
                                            <strong>⚠️ Importante:</strong><br>
                                            • Este enlace es válido por <strong>1 hora</strong><br>
                                            • Solo puedes usarlo una vez<br>
                                            • Si no solicitaste este cambio, ignora este email
                                        </p>
                                    </div>
                                </td>
                            </tr>
                            
                            <!-- Footer -->
                            <tr>
                                <td style="padding: 30px 40px; background-color: #f8f9fa; border-radius: 0 0 8px 8px; text-align: center;">
                                    <p style="margin: 0 0 10px 0; color: #999999; font-size: 14px;">
                                        © 2025 Instacoach. Todos los derechos reservados.
                                    </p>
                                    <p style="margin: 0; color: #999999; font-size: 12px;">
                                        Si tienes problemas, contáctanos en <a href="mailto:support@instacoach.cl" style="color: #667eea;">support@instacoach.cl</a>
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        # Crear versión de texto plano
        text_content = f"""
        Recuperación de Contraseña - Instacoach
        
        Hola,
        
        Recibimos una solicitud para restablecer la contraseña de tu cuenta de {role_display} en Instacoach.
        
        Para crear una nueva contraseña, visita el siguiente enlace:
        {reset_url}
        
        IMPORTANTE:
        - Este enlace es válido por 1 hora
        - Solo puedes usarlo una vez
        - Si no solicitaste este cambio, ignora este email
        
        Si tienes problemas, contáctanos en support@instacoach.cl
        
        © 2025 Instacoach. Todos los derechos reservados.
        """
        
        # Crear mensaje
        message = MIMEMultipart('alternative')
        message['Subject'] = f'Recuperación de Contraseña - Instacoach'
        message['From'] = f'{sender_name} <{sender_email}>'
        message['To'] = user_email
        
        # Adjuntar partes
        part_text = MIMEText(text_content, 'plain', 'utf-8')
        part_html = MIMEText(html_content, 'html', 'utf-8')
        message.attach(part_text)
        message.attach(part_html)
        
        # Enviar email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)
        
        logger.info(f"Password reset email sent successfully to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending password reset email: {str(e)}")
        # En caso de error, registrar URL en logs como fallback
        try:
            reset_url = f"{request.host_url}reset-password/{user_role}/{reset_token}"
            logger.info(f"Fallback - Password reset URL for {user_email}: {reset_url}")
        except:
            pass
        return False

@app.route('/api/admin/forgot-password', methods=['POST'])
def admin_forgot_password():
    """Endpoint para solicitar recuperación de contraseña del admin"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email requerido'}), 400
        
        # Buscar usuario admin con ese email
        admin_user = User.query.filter(
            User.email == email,
            User.role == 'platform_admin',
            User.active == True
        ).first()
        
        # Por seguridad, siempre devolver el mismo mensaje
        # (no revelar si el email existe o no)
        if admin_user:
            # Invalidar tokens anteriores del usuario
            PasswordResetToken.query.filter_by(
                user_id=admin_user.id,
                used=False
            ).update({'used': True})
            db.session.commit()
            
            # Generar nuevo token
            reset_token = generate_reset_token()
            token_record = PasswordResetToken(
                user_id=admin_user.id,
                token=reset_token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            
            db.session.add(token_record)
            db.session.commit()
            
            # Enviar email
            send_password_reset_email(email, reset_token, 'admin')
            
            # Log de seguridad
            log_security_event(
                event_type='password_reset_requested',
                severity='info',
                user_id=admin_user.id,
                username=admin_user.username,
                description=f'Password reset requested for admin {admin_user.email}'
            )
        
        # Siempre devolver éxito (seguridad)
        return jsonify({
            'success': True,
            'message': 'Si el email existe, recibirás instrucciones para restablecer tu contraseña.'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in forgot password: {str(e)}")
        return jsonify({'error': 'Error procesando solicitud'}), 500

@app.route('/reset-password/admin/<token>')
def admin_reset_password_page(token):
    """Página para restablecer contraseña del admin con token"""
    try:
        # Verificar que el token existe y es válido
        token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not token_record:
            logger.warning(f"Token not found in database: {token}")
            return render_template('password_reset_invalid.html', role='admin', reason='not_found')
        
        if not token_record.is_valid():
            logger.warning(f"Token expired or used: {token}")
            return render_template('password_reset_invalid.html', role='admin', reason='expired')
        
        logger.info(f"Valid token accessed: {token} for user_id: {token_record.user_id}")
        return render_template('password_reset_form.html', token=token, role='admin')
        
    except Exception as e:
        logger.error(f"Error in admin_reset_password_page: {str(e)}")
        logger.error(f"Token received: {token}")
        return render_template('password_reset_invalid.html', role='admin', reason='error', error_message=str(e))

@app.route('/api/admin/reset-password', methods=['POST'])
def admin_reset_password():
    """Endpoint para restablecer contraseña del admin con token"""
    try:
        data = request.get_json()
        token = data.get('token', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        if not all([token, new_password, confirm_password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'Las contraseñas no coinciden'}), 400
        
        # Validar fortaleza de contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Verificar token
        token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not token_record or not token_record.is_valid():
            return jsonify({'error': 'Token inválido o expirado'}), 400
        
        # Obtener usuario
        user = token_record.user
        
        # ✨ NUEVO: Validar que la nueva contraseña sea diferente a la actual
        if user.check_password(new_password):
            log_security_event(
                event_type='password_reuse_attempt',
                severity='info',
                user_id=user.id,
                username=user.username,
                description='Intento de reutilizar la misma contraseña en reset (Admin)'
            )
            return jsonify({'error': 'La nueva contraseña debe ser diferente a la contraseña actual'}), 400
        
        # Actualizar contraseña
        user.set_password(new_password)
        db.session.add(user)  # Asegurar que SQLAlchemy detecte el cambio
        
        # Marcar token como usado
        token_record.used = True
        
        db.session.flush()     # Forzar escritura inmediata a BD
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        # Log de seguridad
        log_security_event(
            event_type='password_reset_completed',
            severity='info',
            user_id=user.id,
            username=user.username,
            description=f'Password successfully reset for admin {user.email}'
        )
        
        return jsonify({
            'success': True,
            'message': 'Contraseña restablecida correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error resetting password: {str(e)}")
        return jsonify({'error': 'Error al restablecer contraseña'}), 500

# ============================================================================
# RECUPERACIÓN DE CONTRASEÑA DE COACH
# ============================================================================

@app.route('/api/coach/forgot-password', methods=['POST'])
def coach_forgot_password():
    """Endpoint para solicitar recuperación de contraseña del coach"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email requerido'}), 400
        
        # Buscar usuario coach con ese email
        coach_user = User.query.filter(
            User.email == email,
            User.role == 'coach',
            User.active == True
        ).first()
        
        # Por seguridad, siempre devolver el mismo mensaje
        # (no revelar si el email existe o no)
        if coach_user:
            # Invalidar tokens anteriores del usuario
            PasswordResetToken.query.filter_by(
                user_id=coach_user.id,
                used=False
            ).update({'used': True})
            db.session.commit()
            
            # Generar nuevo token
            reset_token = generate_reset_token()
            token_record = PasswordResetToken(
                user_id=coach_user.id,
                token=reset_token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            
            db.session.add(token_record)
            db.session.commit()
            
            # Enviar email
            send_password_reset_email(email, reset_token, 'coach')
            
            # Log de seguridad
            log_security_event(
                event_type='password_reset_requested',
                severity='info',
                user_id=coach_user.id,
                username=coach_user.username,
                description=f'Password reset requested for coach {coach_user.email}'
            )
        
        # Siempre devolver éxito (seguridad)
        return jsonify({
            'success': True,
            'message': 'Si el email existe, recibirás instrucciones para restablecer tu contraseña.'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in coach forgot password: {str(e)}")
        return jsonify({'error': 'Error procesando solicitud'}), 500

@app.route('/reset-password/coach/<token>')
def coach_reset_password_page(token):
    """Página para restablecer contraseña del coach con token"""
    try:
        # Verificar que el token existe y es válido
        token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not token_record:
            logger.warning(f"Token not found in database: {token}")
            return render_template('password_reset_invalid.html', role='coach', reason='not_found')
        
        if not token_record.is_valid():
            logger.warning(f"Token expired or used: {token}")
            return render_template('password_reset_invalid.html', role='coach', reason='expired')
        
        logger.info(f"Valid token accessed: {token} for user_id: {token_record.user_id}")
        return render_template('password_reset_form.html', token=token, role='coach')
        
    except Exception as e:
        logger.error(f"Error in coach_reset_password_page: {str(e)}")
        logger.error(f"Token received: {token}")
        return render_template('password_reset_invalid.html', role='coach', reason='error', error_message=str(e))

@app.route('/api/coach/reset-password', methods=['POST'])
def coach_reset_password():
    """Endpoint para restablecer contraseña del coach con token"""
    try:
        data = request.get_json()
        token = data.get('token', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        if not all([token, new_password, confirm_password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'Las contraseñas no coinciden'}), 400
        
        # Validar fortaleza de contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Verificar token
        token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not token_record or not token_record.is_valid():
            return jsonify({'error': 'Token inválido o expirado'}), 400
        
        # Obtener usuario
        user = token_record.user
        
        # Actualizar contraseña
        user.set_password(new_password)
        db.session.add(user)  # Asegurar que SQLAlchemy detecte el cambio
        
        # Marcar token como usado
        token_record.used = True
        
        db.session.flush()     # Forzar escritura inmediata a BD
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        # Log de seguridad
        log_security_event(
            event_type='password_reset_completed',
            severity='info',
            user_id=user.id,
            username=user.username,
            description=f'Password successfully reset for coach {user.email}'
        )
        
        return jsonify({
            'success': True,
            'message': 'Contraseña restablecida correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error resetting coach password: {str(e)}")
        return jsonify({'error': 'Error al restablecer contraseña'}), 500

# Endpoint de cambio de contraseña de admin eliminado (duplicado) - usar el de línea 3818

# === ENDPOINTS DE RECUPERACIÓN DE CONTRASEÑA PARA COACHEES ===

@app.route('/api/coachee/forgot-password', methods=['POST'])
def coachee_forgot_password():
    """Endpoint para solicitar recuperación de contraseña del coachee"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email requerido'}), 400
        
        # Buscar usuario coachee con ese email
        coachee_user = User.query.filter(
            User.email == email,
            User.role == 'coachee',
            User.active == True
        ).first()
        
        # Por seguridad, siempre devolver el mismo mensaje
        # (no revelar si el email existe o no)
        if coachee_user:
            # Invalidar tokens anteriores del usuario
            PasswordResetToken.query.filter_by(
                user_id=coachee_user.id,
                used=False
            ).update({'used': True})
            db.session.commit()
            
            # Generar nuevo token
            reset_token = generate_reset_token()
            token_record = PasswordResetToken(
                user_id=coachee_user.id,
                token=reset_token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            
            db.session.add(token_record)
            db.session.commit()
            
            # Enviar email
            send_password_reset_email(email, reset_token, 'coachee')
            
            # Log de seguridad
            log_security_event(
                event_type='password_reset_requested',
                severity='info',
                user_id=coachee_user.id,
                username=coachee_user.username,
                description=f'Password reset requested for coachee {coachee_user.email}'
            )
        
        # Siempre devolver éxito (seguridad)
        return jsonify({
            'success': True,
            'message': 'Si el email existe, recibirás instrucciones para restablecer tu contraseña.'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in coachee forgot password: {str(e)}")
        return jsonify({'error': 'Error procesando solicitud'}), 500

@app.route('/reset-password/coachee/<token>')
def coachee_reset_password_page(token):
    """Página para restablecer contraseña del coachee con token"""
    try:
        # Verificar que el token existe y es válido
        token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not token_record:
            logger.warning(f"Token not found in database: {token}")
            return render_template('password_reset_invalid.html', role='coachee', reason='not_found')
        
        if not token_record.is_valid():
            logger.warning(f"Token expired or used: {token}")
            return render_template('password_reset_invalid.html', role='coachee', reason='expired')
        
        logger.info(f"Valid token accessed: {token} for user_id: {token_record.user_id}")
        return render_template('password_reset_form.html', token=token, role='coachee')
        
    except Exception as e:
        logger.error(f"Error in coachee_reset_password_page: {str(e)}")
        logger.error(f"Token received: {token}")
        return render_template('password_reset_invalid.html', role='coachee', reason='error', error_message=str(e))

@app.route('/api/coachee/reset-password', methods=['POST'])
def coachee_reset_password():
    """Endpoint para restablecer contraseña del coachee con token"""
    try:
        data = request.get_json()
        token = data.get('token', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        if not all([token, new_password, confirm_password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'Las contraseñas no coinciden'}), 400
        
        # Validar fortaleza de contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Verificar token
        token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not token_record or not token_record.is_valid():
            return jsonify({'error': 'Token inválido o expirado'}), 400
        
        # Obtener usuario
        user = token_record.user
        
        # Actualizar contraseña
        user.set_password(new_password)
        db.session.add(user)  # Asegurar que SQLAlchemy detecte el cambio
        
        # Marcar token como usado
        token_record.used = True
        
        db.session.flush()     # Forzar escritura inmediata a BD
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        # Log de seguridad
        log_security_event(
            event_type='password_reset_completed',
            severity='info',
            user_id=user.id,
            username=user.username,
            description=f'Password successfully reset for coachee {user.email}'
        )
        
        return jsonify({
            'success': True,
            'message': 'Contraseña restablecida correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error resetting coachee password: {str(e)}")
        return jsonify({'error': 'Error al restablecer contraseña'}), 500

@app.route('/api/admin/create-coach', methods=['POST'])
@admin_required
def api_admin_create_coach():
    try:
        data = request.get_json()
        
        required_fields = ['username', 'email', 'full_name', 'password']
        if missing_fields := validate_required_fields(data, required_fields):
            return jsonify({'error': f'Campos requeridos: {", ".join(missing_fields)}'}), 400
        
        username, email, full_name, password = data['username'], data['email'], data['full_name'], data['password']
        notification_method = data.get('notification_method', 'email')  # 'email', 'whatsapp', 'none'
        
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
        
        # Obtener nombre del admin actual
        admin_user = getattr(g, 'current_user', None)
        admin_name = admin_user.full_name if admin_user else 'Administrador'
        
        # Enviar notificación según método seleccionado
        notification_result = {'success': True, 'message': 'No se envió notificación'}
        
        if notification_method == 'email':
            notification_result = send_welcome_email_to_new_coach(new_coach, password, admin_name)
        elif notification_method == 'whatsapp':
            notification_result = generate_whatsapp_welcome_message(new_coach, password, admin_name)
        
        response_data = {
            'success': True,
            'message': f'Coach {full_name} creado exitosamente',
            'coach': {
                'id': new_coach.id,
                'username': new_coach.username,
                'email': new_coach.email,
                'full_name': new_coach.full_name,
                'role': new_coach.role,
                'created_at': new_coach.created_at.isoformat() if new_coach.created_at else None
            },
            'notification': notification_result
        }
        
        logger.info(f"✅ Coach creado: {full_name} (ID: {new_coach.id}), notificación: {notification_method}")
        
        return jsonify(response_data), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Error creando coach: {str(e)}", exc_info=True)
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
        # Estadísticas básicas - EXCLUIR usuarios eliminados (soft delete)
        total_users = User.query.filter(User.deleted_at.is_(None)).count()
        total_coaches = User.query.filter_by(role='coach').filter(User.deleted_at.is_(None)).count()
        total_coachees = User.query.filter_by(role='coachee').filter(User.deleted_at.is_(None)).count()
        total_admins = User.query.filter_by(role='platform_admin').filter(User.deleted_at.is_(None)).count()
        total_assessments = AssessmentResult.query.count()
        
        # Usuarios eliminados (soft delete)
        deleted_users = User.query.filter(User.deleted_at.isnot(None)).count()
        
        # Puntuación promedio
        avg_score_result = db.session.query(func.avg(AssessmentResult.score)).scalar()
        avg_score = round(avg_score_result, 1) if avg_score_result else 0
        
        # Evaluaciones del último mes
        last_month = datetime.utcnow() - timedelta(days=30)
        recent_assessments = AssessmentResult.query.filter(AssessmentResult.completed_at >= last_month).count()  # type: ignore
        
        # Usuarios activos/inactivos (excluyendo eliminados)
        active_users = User.query.filter_by(active=True).filter(User.deleted_at.is_(None)).count()
        inactive_users = User.query.filter_by(active=False).filter(User.deleted_at.is_(None)).count()
        
        return jsonify({
            'success': True,
            'total_users': total_users,
            'total_coaches': total_coaches,
            'total_coachees': total_coachees,
            'total_admins': total_admins,
            'total_assessments': total_assessments,
            'deleted_users': deleted_users,
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

# ============================================================================
# ENDPOINTS DE GESTIÓN DE USUARIOS (ADMIN)
# ============================================================================

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_get_all_users():
    """Obtener todos los usuarios (coaches y coachees) con filtros opcionales"""
    try:
        # Parámetros de filtrado
        role = request.args.get('role')  # 'coach', 'coachee', or None for all
        status = request.args.get('status')  # 'active', 'inactive', or None for all
        search = request.args.get('search', '').strip()
        
        # Query base - EXCLUIR usuarios eliminados (soft delete)
        query = User.query.filter(
            User.role.in_(['coach', 'coachee']),
            User.deleted_at.is_(None)  # Solo usuarios NO eliminados
        )
        
        # Aplicar filtros
        if role:
            query = query.filter_by(role=role)
        
        if status:
            is_active = status == 'active'
            query = query.filter_by(active=is_active)
        
        if search:
            query = query.filter(
                or_(
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%'),
                    User.full_name.ilike(f'%{search}%')
                )
            )
        
        # Ordenar por fecha de creación (más recientes primero)
        users = query.order_by(desc(User.created_at)).all()
        
        users_data = []
        for user in users:
            user_dict = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'is_active': user.is_active,
                'avatar_url': user.avatar_url,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
            }
            
            # Datos específicos por rol
            if user.role == 'coach':
                coachees_count = User.query.filter_by(coach_id=user.id, role='coachee').count()
                assessments_count = AssessmentResult.query.filter_by(coach_id=user.id).count()
                user_dict['coachees_count'] = coachees_count
                user_dict['assessments_count'] = assessments_count
            elif user.role == 'coachee':
                coach = User.query.get(user.coach_id) if user.coach_id else None
                assessments_count = AssessmentResult.query.filter_by(user_id=user.id).count()
                user_dict['coach_name'] = coach.full_name if coach else 'Sin asignar'
                user_dict['coach_id'] = user.coach_id
                user_dict['assessments_count'] = assessments_count
            
            users_data.append(user_dict)
        
        logger.info(f"✅ ADMIN: Listado de usuarios - Total: {len(users_data)}, Filtros: role={role}, status={status}, search={search}")
        
        return jsonify({
            'success': True,
            'users': users_data,
            'total': len(users_data)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ ADMIN: Error obteniendo usuarios: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo usuarios: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    """Actualizar información de un usuario"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # No permitir editar admins
        if user.role == 'platform_admin':
            return jsonify({'error': 'No se pueden editar cuentas de administrador'}), 403
        
        data = request.get_json()
        
        # Campos editables
        if 'full_name' in data:
            full_name = data.get('full_name', '').strip()
            if not full_name or len(full_name) < 3:
                return jsonify({'error': 'El nombre completo debe tener al menos 3 caracteres'}), 400
            user.full_name = sanitize_string(full_name, 200)
        
        if 'email' in data:
            email = data.get('email', '').strip().lower()
            if not validate_email(email):
                return jsonify({'error': 'Email inválido'}), 400
            
            # Verificar que el email no esté en uso por otro usuario
            existing = User.query.filter(User.email == email, User.id != user_id).first()
            if existing:
                return jsonify({'error': 'El email ya está en uso'}), 400
            
            user.email = email
        
        if 'username' in data:
            username = data.get('username', '').strip().lower()
            if not validate_username(username):
                return jsonify({'error': 'Username inválido (mínimo 3 caracteres, solo letras, números, guiones y guiones bajos)'}), 400
            
            # Verificar que el username no esté en uso por otro usuario
            existing = User.query.filter(User.username == username, User.id != user_id).first()
            if existing:
                return jsonify({'error': 'El username ya está en uso'}), 400
            
            user.username = username
        
        # Solo para coachees: cambiar coach asignado
        if user.role == 'coachee' and 'coach_id' in data:
            coach_id = data.get('coach_id')
            if coach_id:
                coach = User.query.filter_by(id=coach_id, role='coach').first()
                if not coach:
                    return jsonify({'error': 'Coach no encontrado'}), 404
                user.coach_id = coach_id
            else:
                user.coach_id = None
        
        db.session.commit()
        
        logger.info(f"✅ ADMIN: Usuario actualizado - ID: {user_id}, Username: {user.username}")
        log_security_event('user_updated', 'info', 
                          user_id=current_user.id, 
                          username=current_user.username,
                          description=f'Admin actualizó usuario {user.username} (ID: {user_id})')
        
        return jsonify({
            'success': True,
            'message': 'Usuario actualizado exitosamente',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'is_active': user.is_active,
                'coach_id': user.coach_id
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error actualizando usuario: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error actualizando usuario: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def api_admin_toggle_user_status(user_id):
    """Activar/Desactivar (bloquear/desbloquear) un usuario"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # No permitir bloquear admins
        if user.role == 'platform_admin':
            return jsonify({'error': 'No se pueden bloquear cuentas de administrador'}), 403
        
        # No permitirse bloquear a sí mismo
        if user.id == current_user.id:
            return jsonify({'error': 'No puedes bloquear tu propia cuenta'}), 403
        
        # Toggle status
        user.active = not user.active
        db.session.commit()
        
        status_text = 'activado' if user.active else 'bloqueado'
        logger.info(f"✅ ADMIN: Usuario {status_text} - ID: {user_id}, Username: {user.username}")
        log_security_event('user_status_changed', 'warning' if not user.active else 'info',
                          user_id=current_user.id,
                          username=current_user.username,
                          description=f'Admin {status_text} usuario {user.username} (ID: {user_id})')
        
        return jsonify({
            'success': True,
            'message': f'Usuario {status_text} exitosamente',
            'is_active': user.active
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error cambiando estado de usuario: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error cambiando estado: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    """SOFT DELETE - Marcar usuario como eliminado (recuperable)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Verificar si ya está eliminado
        if user.deleted_at:
            return jsonify({'error': 'Usuario ya está eliminado'}), 400
        
        # No permitir eliminar admins
        if user.role == 'platform_admin':
            return jsonify({'error': 'No se pueden eliminar cuentas de administrador'}), 403
        
        # No permitirse eliminar a sí mismo
        if user.id == current_user.id:
            return jsonify({'error': 'No puedes eliminar tu propia cuenta'}), 403
        
        # Obtener datos del request
        data = request.get_json() or {}
        deletion_reason = data.get('reason', '').strip()
        
        # Validar razón de eliminación
        if not deletion_reason or len(deletion_reason) < 10:
            return jsonify({'error': 'Debes proporcionar una razón de eliminación (mínimo 10 caracteres)'}), 400
        
        username = user.username
        user_email = user.email
        
        # SOFT DELETE: Marcar como eliminado
        user.deleted_at = datetime.utcnow()
        user.deleted_by = current_user.id
        user.deletion_reason = deletion_reason[:1000]  # Limitar a 1000 caracteres
        user.active = False  # Desactivar cuenta
        
        # Si es coach, desasignar sus coachees (no eliminar la relación, solo marcar)
        if user.role == 'coach':
            coachees = User.query.filter_by(coach_id=user_id).all()
            for coachee in coachees:
                coachee.coach_id = None  # Desasignar coach
            logger.info(f"✅ ADMIN: Coachees del coach {username} desasignados")
        
        db.session.commit()
        
        logger.info(f"🗑️ ADMIN: Usuario marcado como eliminado (SOFT DELETE) - {username} (ID: {user_id})")
        logger.info(f"   Razón: {deletion_reason}")
        log_security_event('user_soft_deleted', 'warning',
                          user_id=current_user.id,
                          username=current_user.username,
                          description=f'Admin soft-deleted user {username} (ID: {user_id}). Reason: {deletion_reason}')
        
        return jsonify({
            'success': True,
            'message': f'Usuario {username} eliminado correctamente (recuperable)',
            'deletion_type': 'soft',
            'deleted_at': user.deleted_at.isoformat() if user.deleted_at else None,
            'can_restore': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error eliminando usuario: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error eliminando usuario: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>/hard-delete', methods=['DELETE'])
@admin_required
def api_admin_hard_delete_user(user_id):
    """HARD DELETE - Eliminar usuario PERMANENTEMENTE (no recuperable)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # No permitir eliminar admins
        if user.role == 'platform_admin':
            return jsonify({'error': 'No se pueden eliminar cuentas de administrador'}), 403
        
        # No permitirse eliminar a sí mismo
        if user.id == current_user.id:
            return jsonify({'error': 'No puedes eliminar tu propia cuenta'}), 403
        
        # Requiere confirmación explícita
        data = request.get_json() or {}
        confirmation = data.get('confirm', '').strip().upper()
        
        if confirmation != 'DELETE PERMANENTLY':
            return jsonify({
                'error': 'Confirmación requerida',
                'required_confirmation': 'DELETE PERMANENTLY',
                'warning': 'Esta acción es IRREVERSIBLE y eliminará TODOS los datos del usuario'
            }), 400
        
        username = user.username
        user_email = user.email
        user_role = user.role
        
        # ELIMINACIÓN EN CASCADA - PERMANENTE
        try:
            # Si es coach, reasignar coachees a NULL
            if user.role == 'coach':
                coachees = User.query.filter_by(coach_id=user_id).all()
                for coachee in coachees:
                    coachee.coach_id = None
                
                # Eliminar evaluaciones creadas por este coach
                AssessmentResult.query.filter_by(coach_id=user_id).delete()
            
            # Si es coachee, eliminar sus evaluaciones
            if user.role == 'coachee':
                AssessmentResult.query.filter_by(user_id=user_id).delete()
                Response.query.filter_by(user_id=user_id).delete()
                AssessmentHistory.query.filter_by(user_id=user_id).delete()
                
                # Eliminar progreso de tareas
                coachee_tasks = Task.query.filter_by(coachee_id=user_id).all()
                for task in coachee_tasks:
                    TaskProgress.query.filter_by(task_id=task.id).delete()
            
            # Eliminar tokens de reseteo
            PasswordResetToken.query.filter_by(user_id=user_id).delete()
            
            # Eliminar invitaciones
            Invitation.query.filter_by(coach_id=user_id).delete()
            Invitation.query.filter_by(coachee_id=user_id).delete()
            
            # Eliminar tareas
            Task.query.filter_by(coach_id=user_id).delete()
            Task.query.filter_by(coachee_id=user_id).delete()
            
            # Eliminar planes de desarrollo
            DevelopmentPlan.query.filter_by(coach_id=user_id).delete()
            DevelopmentPlan.query.filter_by(coachee_id=user_id).delete()
            
            # Eliminar contenido
            Content.query.filter_by(coach_id=user_id).delete()
            Content.query.filter_by(coachee_id=user_id).delete()
            
            # Eliminar notificaciones
            Notification.query.filter_by(user_id=user_id).delete()
            
            # Actualizar FKs que apuntan a este usuario
            if user.role == 'platform_admin':
                db.session.execute(db.text("UPDATE coach_request SET reviewed_by = NULL WHERE reviewed_by = :user_id"), {'user_id': user_id})
            
            # Eliminar el usuario PERMANENTEMENTE
            db.session.execute(db.text("DELETE FROM user WHERE id = :user_id"), {'user_id': user_id})
            db.session.commit()
            
            logger.warning(f"🔥 ADMIN: Usuario ELIMINADO PERMANENTEMENTE (HARD DELETE) - {username} (ID: {user_id})")
            log_security_event('user_hard_deleted', 'critical',
                              user_id=current_user.id,
                              username=current_user.username,
                              description=f'Admin PERMANENTLY deleted user {username} (ID: {user_id}, Role: {user_role}, Email: {user_email})')
            
            return jsonify({
                'success': True,
                'message': f'Usuario {username} eliminado PERMANENTEMENTE',
                'deletion_type': 'hard',
                'warning': 'Esta eliminación es IRREVERSIBLE. Todos los datos han sido destruidos.',
                'can_restore': False
            }), 200
            
        except Exception as delete_error:
            db.session.rollback()
            logger.error(f"❌ ADMIN: Error en eliminación permanente: {str(delete_error)}", exc_info=True)
            return jsonify({'error': f'Error en eliminación permanente: {str(delete_error)}'}), 500
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error en eliminación permanente: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error en eliminación permanente: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>/restore', methods=['POST'])
@admin_required
def api_admin_restore_user(user_id):
    """RESTAURAR usuario eliminado (soft delete)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Verificar que el usuario está eliminado
        if not user.deleted_at:
            return jsonify({'error': 'Este usuario no está eliminado'}), 400
        
        # Restaurar usuario
        user.deleted_at = None
        user.deleted_by = None
        user.deletion_reason = None
        user.active = True
        
        db.session.commit()
        
        logger.info(f"♻️ ADMIN: Usuario restaurado - {user.username} (ID: {user_id})")
        log_security_event('user_restored', 'info',
                          user_id=current_user.id,
                          username=current_user.username,
                          description=f'Admin restored user {user.username} (ID: {user_id})')
        
        return jsonify({
            'success': True,
            'message': f'Usuario {user.username} restaurado correctamente',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'active': user.active,
                'restored_at': datetime.utcnow().isoformat()
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error restaurando usuario: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error restaurando usuario: {str(e)}'}), 500

@app.route('/api/admin/users/deleted', methods=['GET'])
@admin_required
def api_admin_list_deleted_users():
    """Listar usuarios eliminados (soft delete) - recuperables"""
    try:
        deleted_users = User.query.filter(
            User.deleted_at.isnot(None)
        ).order_by(User.deleted_at.desc()).all()
        
        users_data = []
        for user in deleted_users:
            deleted_by_admin = None
            if user.deleted_by:
                admin = User.query.get(user.deleted_by)
                if admin:
                    deleted_by_admin = {
                        'id': admin.id,
                        'username': admin.username,
                        'full_name': admin.full_name
                    }
            
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'deleted_at': user.deleted_at.isoformat() if user.deleted_at else None,
                'deleted_by': deleted_by_admin,
                'deletion_reason': user.deletion_reason,
                'can_restore': True
            })
        
        return jsonify({
            'success': True,
            'deleted_users': users_data,
            'count': len(users_data)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ ADMIN: Error listando usuarios eliminados: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error listando usuarios eliminados: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def api_admin_reset_user_password(user_id):
    """Resetear contraseña de un usuario - genera contraseña temporal y fuerza cambio"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # No permitir resetear contraseñas de admins
        if user.role == 'platform_admin':
            return jsonify({'error': 'No se pueden resetear contraseñas de administrador'}), 403
        
        # Generar contraseña temporal segura
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        # Actualizar contraseña
        user.set_password(temp_password)
        user.original_password = temp_password  # Guardar para mostrar al admin
        db.session.commit()
        
        logger.info(f"🔐 ADMIN: Contraseña reseteada - Usuario: {user.username} (ID: {user_id})")
        log_security_event('password_reset_by_admin', 'warning',
                          user_id=current_user.id,
                          username=current_user.username,
                          description=f'Admin reseteó contraseña de {user.username} (ID: {user_id})')
        
        return jsonify({
            'success': True,
            'message': 'Contraseña reseteada exitosamente',
            'temp_password': temp_password,
            'instructions': 'El usuario deberá cambiar esta contraseña en su próximo inicio de sesión'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error reseteando contraseña: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error reseteando contraseña: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>/change-password', methods=['POST'])
@admin_required
def api_admin_change_user_password(user_id):
    """Cambiar contraseña de un usuario a una específica"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # No permitir cambiar contraseñas de admins
        if user.role == 'platform_admin':
            return jsonify({'error': 'No se pueden cambiar contraseñas de administrador'}), 403
        
        data = request.get_json()
        new_password = data.get('new_password', '').strip()
        
        # Validar contraseña
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Actualizar contraseña
        user.set_password(new_password)
        user.original_password = None  # Limpiar contraseña original si existía
        db.session.commit()
        
        logger.info(f"🔐 ADMIN: Contraseña cambiada - Usuario: {user.username} (ID: {user_id})")
        log_security_event('password_changed_by_admin', 'warning',
                          user_id=current_user.id,
                          username=current_user.username,
                          description=f'Admin cambió contraseña de {user.username} (ID: {user_id})')
        
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ ADMIN: Error cambiando contraseña: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error cambiando contraseña: {str(e)}'}), 500

# ============================================================================
# FIN DE ENDPOINTS DE GESTIÓN DE USUARIOS (ADMIN)
# ============================================================================

# Rutas de coach
@app.route('/coach-login')
def coach_login_page():
    return render_template('coach_login.html')

@app.route('/api/coach/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_coach_login():
    try:
        data = request.get_json()
        
        # DEBUG: Log incoming data
        logger.info(f"🔍 DEBUG Coach Login - Raw data: {data}")
        logger.info(f"🔍 DEBUG Coach Login - Headers: User-Agent={request.headers.get('User-Agent')}")
        
        # Validar y sanitizar inputs
        valid, result = validate_and_sanitize_login_input(data)
        if not valid:
            logger.warning(f"Coach login attempt with invalid input from {request.remote_addr}: {result}")
            return jsonify({'error': result}), 400
        
        username = result['username_or_email']
        password = result['password']
        
        # DEBUG: Log sanitized credentials
        logger.info(f"🔍 DEBUG Coach Login - Username: '{username}', Password length: {len(password)}")
        
        # SEGURIDAD: Verificar bloqueo de cuenta por intentos fallidos
        is_locked, remaining_time, attempts = check_account_lockout(username)
        if is_locked:
            logger.warning(f"🔒 COACH ACCOUNT LOCKED: {username} - {attempts} failed attempts, {remaining_time} minutes remaining")
            return jsonify({
                'error': f'Cuenta temporalmente bloqueada por seguridad. Intenta nuevamente en {remaining_time} minutos.',
                'locked': True,
                'remaining_minutes': remaining_time
            }), 429
        
        # SEGURIDAD: Solo aceptar username (no email) para reducir vector de ataque
        coach_user = User.query.filter(User.username == username, User.role == 'coach').first()  # type: ignore
        
        if coach_user and coach_user.check_password(password) and coach_user.is_active:
            # Usar sesión específica para coach (sin limpiar otras sesiones)
            session['coach_user_id'] = coach_user.id
            
            # NO usar login_user() para evitar conflictos entre sesiones
            session.permanent = True
            coach_user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Registrar login exitoso en auditoría
            log_successful_login(coach_user)
            
            logger.info(f"Successful coach login for {coach_user.username} (ID: {coach_user.id}) from {request.remote_addr}")
            
            return jsonify({
                'success': True,
                'user': create_user_response(coach_user),
                'redirect_url': '/coach-feed'
            }), 200
        else:
            # Registrar login fallido en auditoría
            log_failed_login(username, 'Invalid coach credentials')
            
            # Verificar si hay ataque sostenido de fuerza bruta
            if check_failed_login_threshold(request.remote_addr):
                send_security_alert(
                    event_type='sustained_attack',
                    details={
                        'ip_address': request.remote_addr,
                        'username': username,
                        'user_role': 'coach',
                        'attempts': '>5',
                        'time_window': '10 minutes',
                        'description': f'Ataque de fuerza bruta detectado: >5 intentos fallidos de login de coach en 10 minutos desde IP {request.remote_addr}'
                    }
                )
            
            logger.warning(f"Failed coach login attempt for username '{username}' from {request.remote_addr}")
            return jsonify({'error': 'Credenciales de coach inválidas'}), 401
            
    except Exception as e:
        logger.error(f"Error in coach login: {str(e)}")
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@app.route('/api/coach/profile', methods=['GET'])
@coach_session_required
def api_coach_get_profile():
    try:
        coachees_count = User.query.filter_by(coach_id=g.current_user.id, role='coachee').count()
        assessments_count = AssessmentResult.query.filter_by(coach_id=g.current_user.id).count()
        
        return jsonify({
            'success': True,
            'profile': {
                **create_user_response(g.current_user),
                'coachees_count': coachees_count,
                'assessments_count': assessments_count,
                'created_at': g.current_user.created_at.isoformat() if g.current_user.created_at else None,
                'last_login': g.current_user.last_login.isoformat() if g.current_user.last_login else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500


@app.route('/api/coach/session-requests', methods=['GET'])
@coach_session_required
def api_coach_session_requests():
    """Obtener solicitudes de sesión pendientes (CoachingSession con proposed_by='coachee' y status='pending')"""
    try:
        current_coach = g.current_user
        status = request.args.get('status', 'pending')

        # Consultar CoachingSession creadas por coachees para este coach
        query = CoachingSession.query.filter(
            CoachingSession.coach_id == current_coach.id,
            CoachingSession.proposed_by == 'coachee'
        )

        if status != 'all':
            query = query.filter(CoachingSession.status == status)

        sessions = query.order_by(CoachingSession.created_at.desc()).all()

        requests_data = []
        for s in sessions:
            coachee_user = User.query.get(s.coachee_id) if s.coachee_id else None
            requests_data.append({
                'id': s.id,
                'coachee_id': s.coachee_id,
                'coachee_name': coachee_user.full_name if coachee_user else 'Coachee',
                'coachee_email': coachee_user.email if coachee_user else None,
                'title': s.title or 'Sesión de Coaching',
                'description': s.description,
                'preferred_date': s.session_date.isoformat() if s.session_date else None,
                'start_time': s.start_time.strftime('%H:%M') if s.start_time else None,
                'end_time': s.end_time.strftime('%H:%M') if s.end_time else None,
                'location': s.location or 'Virtual',
                'status': s.status,
                'notes': s.notes,
                'created_at': s.created_at.isoformat() if s.created_at else None,
                'updated_at': s.updated_at.isoformat() if s.updated_at else None
            })

        logger.info(f"📋 Coach {current_coach.username} retrieved {len(requests_data)} session requests (status: {status})")

        return jsonify({
            'success': True,
            'requests': requests_data,
            'total': len(requests_data)
        }), 200

    except Exception as e:
        logger.error(f"Error getting session requests: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo solicitudes: {str(e)}'}), 500


@app.route('/api/coach/session-requests/<int:request_id>', methods=['PUT'])
@coach_session_required
def api_coach_update_session_request(request_id):
    """Actualizar notas de una solicitud de sesión"""
    try:
        current_coach = g.current_user
        data = request.get_json()

        session = CoachingSession.query.filter_by(id=request_id, coach_id=current_coach.id).first()
        if not session:
            return jsonify({'error': 'Solicitud no encontrada'}), 404

        if 'status' in data:
            session.status = data['status']
        if 'notes' in data:
            session.notes = data['notes']

        session.updated_at = datetime.utcnow()
        db.session.commit()

        logger.info(f"✅ Coach {current_coach.username} updated session request {request_id}")

        return jsonify({
            'success': True,
            'message': 'Solicitud actualizada exitosamente'
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating session request: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error actualizando solicitud: {str(e)}'}), 500


@app.route('/api/coach/session-requests/<int:request_id>/accept', methods=['POST'])
@coach_session_required
def api_coach_accept_session_request_v2(request_id):
    """Aceptar una solicitud de sesión — confirma la CoachingSession"""
    try:
        current_coach = g.current_user

        session = CoachingSession.query.filter_by(
            id=request_id,
            coach_id=current_coach.id,
            status='pending',
            proposed_by='coachee'
        ).first()

        if not session:
            logger.warning(f"❌ ACEPTAR: CoachingSession {request_id} no encontrada o no está pendiente")
            return jsonify({'error': 'Solicitud no encontrada'}), 404

        session.status = 'confirmed'
        session.updated_at = datetime.utcnow()

        # Notificar al coachee
        if session.coachee_id:
            coachee_name = session.coachee.full_name if session.coachee else 'Coachee'
            date_str = session.session_date.strftime('%d/%m/%Y') if session.session_date else ''
            time_str = session.start_time.strftime('%H:%M') if session.start_time else ''
            notif = Notification(
                user_id=session.coachee_id,
                type='session_confirmed',
                title='Sesión confirmada',
                message=f'Tu sesión del {date_str} a las {time_str} ha sido confirmada por tu coach.',
                related_id=session.id,
                related_type='session'
            )
            db.session.add(notif)

        db.session.commit()

        logger.info(f"✅ ACEPTADA: CoachingSession {request_id} confirmada por coach {current_coach.username}")

        return jsonify({
            'success': True,
            'message': 'Sesión confirmada exitosamente.'
        }), 200

    except Exception as e:
        logger.error(f"Error en api_coach_accept_session_request_v2: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error aceptando solicitud: {str(e)}'}), 500


@app.route('/api/coach/session-requests/<int:request_id>/reject', methods=['POST'])
@coach_session_required
def api_coach_reject_session_request_v2(request_id):
    """Rechazar una solicitud de sesión — cancela la CoachingSession"""
    try:
        current_coach = g.current_user
        data = request.get_json() or {}
        reason = data.get('reason', 'Sin motivo especificado')

        session = CoachingSession.query.filter_by(
            id=request_id,
            coach_id=current_coach.id,
            status='pending',
            proposed_by='coachee'
        ).first()

        if not session:
            logger.warning(f"❌ RECHAZAR: CoachingSession {request_id} no encontrada o no está pendiente")
            return jsonify({'error': 'Solicitud no encontrada'}), 404

        session.status = 'cancelled'
        session.notes = f"Rechazada por coach: {reason}"
        session.updated_at = datetime.utcnow()

        # Notificar al coachee
        if session.coachee_id:
            date_str = session.session_date.strftime('%d/%m/%Y') if session.session_date else ''
            notif = Notification(
                user_id=session.coachee_id,
                type='session_rejected',
                title='Sesión no confirmada',
                message=f'Tu solicitud de sesión del {date_str} no fue confirmada. Motivo: {reason}',
                related_id=session.id,
                related_type='session'
            )
            db.session.add(notif)

        db.session.commit()

        logger.info(f"❌ RECHAZADA: CoachingSession {request_id} rechazada por {current_coach.username}. Motivo: {reason}")

        return jsonify({
            'success': True,
            'message': 'Solicitud rechazada correctamente'
        }), 200

    except Exception as e:
        logger.error(f"Error en api_coach_reject_session_request_v2: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error rechazando solicitud: {str(e)}'}), 500


@app.route('/api/coach/session-requests/<int:request_id>/propose', methods=['POST'])
@coach_session_required
def api_coach_propose_session_time_v2(request_id):
    """Proponer un horario alternativo — crea nueva CoachingSession con status='proposed'"""
    try:
        current_coach = g.current_user
        data = request.get_json() or {}

        original = CoachingSession.query.filter_by(
            id=request_id,
            coach_id=current_coach.id,
            status='pending',
            proposed_by='coachee'
        ).first()

        if not original:
            logger.warning(f"❌ PROPONER: CoachingSession {request_id} no encontrada o no está pendiente")
            return jsonify({'error': 'Solicitud no encontrada'}), 404

        proposed_date_str = data.get('proposed_date')
        proposed_start_time_str = data.get('proposed_start_time')
        proposed_end_time_str = data.get('proposed_end_time')
        message = data.get('message', '')

        if not all([proposed_date_str, proposed_start_time_str, proposed_end_time_str]):
            return jsonify({'error': 'Faltan datos requeridos (fecha, hora inicio, hora fin)'}), 400

        # Marcar la solicitud original como resuelta con propuesta
        original.status = 'proposed'
        original.proposal_message = message or None
        original.updated_at = datetime.utcnow()

        # Crear nueva sesión propuesta por el coach
        proposed_date = datetime.strptime(proposed_date_str, '%Y-%m-%d').date()
        proposed_start = datetime.strptime(proposed_start_time_str, '%H:%M').time()
        proposed_end = datetime.strptime(proposed_end_time_str, '%H:%M').time()

        new_session = CoachingSession(
            coach_id=current_coach.id,
            coachee_id=original.coachee_id,
            session_date=proposed_date,
            start_time=proposed_start,
            end_time=proposed_end,
            status='proposed',
            title=original.title or 'Sesión de Coaching',
            description=original.description,
            location=original.location,
            proposed_by='coach',
            proposal_message=message or None,
            original_session_id=original.id,
            session_type='coaching'
        )
        db.session.add(new_session)

        # Notificar al coachee
        if original.coachee_id:
            notif = Notification(
                user_id=original.coachee_id,
                type='session_proposed',
                title='Propuesta de horario',
                message=f'Tu coach propuso un nuevo horario: {proposed_date_str} de {proposed_start_time_str} a {proposed_end_time_str}.',
                related_id=original.id,
                related_type='session'
            )
            db.session.add(notif)

        db.session.commit()

        logger.info(f"📅 PROPUESTA: Coach {current_coach.username} propuso horario alternativo para CoachingSession {request_id}")

        return jsonify({
            'success': True,
            'message': 'Propuesta de horario enviada al coachee.'
        }), 200

    except Exception as e:
        logger.error(f"Error en api_coach_propose_session_time_v2: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error enviando propuesta: {str(e)}'}), 500


@app.route('/api/coach/upload-avatar', methods=['POST'])
@coach_session_required
def api_coach_upload_avatar():
    """Upload avatar para coach"""
    try:
        if 'avatar' not in request.files:
            return jsonify({'success': False, 'error': 'No se recibió ningún archivo'}), 400
        
        file = request.files['avatar']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No se seleccionó ningún archivo'}), 400
        
        # Validar tipo de archivo
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Tipo de archivo no permitido'}), 400
        
        # Generar nombre único para el archivo
        unique_filename = f"{g.current_user.id}_{uuid.uuid4().hex[:8]}.{file_ext}"
        
        # Guardar en el directorio static/avatars
        avatars_dir = os.path.join(app.root_path, 'static', 'avatars')
        os.makedirs(avatars_dir, exist_ok=True)
        
        file_path = os.path.join(avatars_dir, unique_filename)
        file.save(file_path)
        
        # Actualizar URL del avatar en la base de datos
        avatar_url = f"/static/avatars/{unique_filename}"
        g.current_user.avatar_url = avatar_url
        db.session.commit()
        
        logger.info(f"Avatar uploaded for coach {g.current_user.id}: {avatar_url}")
        
        return jsonify({
            'success': True,
            'avatar_url': avatar_url
        }), 200
        
    except Exception as e:
        logger.error(f"Error uploading coach avatar: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Endpoint de cambio de contraseña de coach eliminado (duplicado) - usar el de línea 3886

@app.route('/api/coach/set-avatar-url', methods=['POST'])
@coach_session_required
def api_coach_set_avatar_url():
    """Establecer URL de avatar predefinido para coach"""
    try:
        data = request.get_json()
        
        avatar_url = data.get('avatar_url')
        
        if not avatar_url:
            return jsonify({'success': False, 'error': 'URL del avatar es requerida'}), 400
        
        # Validar URLs de S3 (si es una URL de AWS)
        if 's3' in avatar_url.lower() and 'amazonaws.com' in avatar_url.lower():
            is_valid, error_msg = validate_s3_url(avatar_url)
            if not is_valid:
                logger.warning(f"Invalid S3 URL rejected for coach {g.current_user.id}: {avatar_url}")
                log_suspicious_activity(
                    description=f'Attempted to set invalid S3 URL as avatar: {error_msg}',
                    user_id=g.current_user.id,
                    username=g.current_user.username,
                    severity='warning'
                )
                return jsonify({'success': False, 'error': f'URL de S3 no válida: {error_msg}'}), 400
        else:
            # Validar que la URL sea de un servicio permitido (avatares externos)
            allowed_domains = ['pravatar.cc', 'ui-avatars.com', 'robohash.org', 'i.pravatar.cc']
            from urllib.parse import urlparse
            parsed_url = urlparse(avatar_url)
            
            if not any(domain in parsed_url.netloc for domain in allowed_domains):
                # Si es una URL local (empieza con /static/), también permitirla
                if not avatar_url.startswith('/static/'):
                    return jsonify({'success': False, 'error': 'URL de avatar no permitida'}), 400
        
        # Actualizar URL del avatar en la base de datos
        g.current_user.avatar_url = avatar_url
        db.session.commit()
        
        logger.info(f"Avatar URL set for coach {g.current_user.id}: {avatar_url}")
        
        return jsonify({
            'success': True,
            'avatar_url': avatar_url
        }), 200
        
    except Exception as e:
        logger.error(f"Error setting coach avatar URL: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Rutas de evaluación
@app.route('/api/questions', methods=['GET'])
@either_session_required
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
            'order': q.order,
            'dimension': q.dimension
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

def update_score_history(assessment_result, new_score, max_history=10):
    """
    Actualiza el historial de puntajes manteniendo un límite máximo de intentos.
    AHORA TAMBIÉN guarda en la tabla AssessmentHistory para análisis de progreso.
    """
    # Inicializar score_history si no existe
    if assessment_result.score_history is None:
        assessment_result.score_history = []
    
    # Calcular número de intento actual
    attempt_number = len(assessment_result.score_history) + 1
    
    # 📊 Calcular porcentaje CORRECTO usando escala Likert
    total_questions = assessment_result.total_questions or 1  # Evitar división por cero
    max_possible_score = total_questions * LIKERT_SCALE_MAX  # Total máximo posible (preguntas × 5)
    score_percentage = round((new_score / max_possible_score) * 100, 2)
    
    # Crear nuevo registro de intento en JSON
    new_attempt = {
        'score': new_score,
        'score_percentage': score_percentage,
        'completed_at': datetime.utcnow().isoformat(),
        'attempt_number': attempt_number
    }
    
    # Agregar nuevo intento al JSON
    assessment_result.score_history.append(new_attempt)
    
    # Mantener solo los últimos max_history intentos en JSON
    if len(assessment_result.score_history) > max_history:
        assessment_result.score_history = assessment_result.score_history[-max_history:]
        
    # Actualizar números de intento después del recorte
    for i, attempt in enumerate(assessment_result.score_history, 1):
        attempt['attempt_number'] = i
    
    # 🆕 NUEVO: Guardar en tabla AssessmentHistory para análisis completo
    try:
        history_entry = AssessmentHistory(
            user_id=assessment_result.user_id,
            assessment_id=assessment_result.assessment_id,
            score=score_percentage,  # 📊 Guardamos el PORCENTAJE, no el score raw
            total_questions=assessment_result.total_questions,
            completed_at=datetime.utcnow(),
            result_text=assessment_result.result_text,
            dimensional_scores=assessment_result.dimensional_scores,
            attempt_number=attempt_number,
            coach_id=assessment_result.coach_id
        )
        db.session.add(history_entry)
        db.session.flush()  # Flush para asignar ID sin hacer commit todavía
        logger.info(f"📊 HISTORY: Saved attempt #{attempt_number} to AssessmentHistory (ID: {history_entry.id}, Score: {score_percentage}%)")
    except Exception as e:
        logger.error(f"❌ HISTORY: Error saving to AssessmentHistory: {str(e)}")
        # No fallar si hay error en historial, continuar con el proceso principal
    
    return len(assessment_result.score_history)

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
        
        logger.info(f"SAVE_ASSESSMENT: Processing assessment_id = {assessment_id}")
        
        # Verificar current_user de forma segura
        try:
            if current_user.is_authenticated:
                logger.debug(f"SAVE_ASSESSMENT: Authenticated user: {current_user.role} (ID: {current_user.id})")
        except Exception as e:
            logger.debug(f"SAVE_ASSESSMENT: Cannot access current_user: {e}")
        
        # Obtener usuario actual (regular o temporal)
        current_coachee = get_current_coachee()
        if not current_coachee:
            logger.error(f"SAVE_ASSESSMENT: Usuario no encontrado en sesión")
            return jsonify({'error': 'Usuario no encontrado'}), 401
        
        logger.info(f"SAVE_ASSESSMENT: Processing for coachee {current_coachee.username} (ID: {current_coachee.id})")
        
        # Detectar tipo de evaluación y usar función de cálculo apropiada
        # Convertir a entero para asegurar comparación correcta
        assessment_id_int = int(assessment_id) if assessment_id else DEFAULT_ASSESSMENT_ID
        
        if assessment_id_int == 2:  # Evaluación DISC de Personalidad
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_disc_score function")
            score, result_text, dimensional_scores = calculate_disc_score(responses)
        elif assessment_id_int == 3:  # Evaluación de Inteligencia Emocional
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_emotional_intelligence_score function")
            score, result_text, dimensional_scores = calculate_emotional_intelligence_score(responses)
        elif assessment_id_int == 4:  # Evaluación de Habilidades de Liderazgo
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_leadership_score function")
            score, result_text, dimensional_scores = calculate_leadership_score(responses)
        elif assessment_id_int == 5:  # Assessment de Trabajo en Equipo
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_teamwork_score function")
            score, result_text, dimensional_scores = calculate_teamwork_score(responses)
        elif assessment_id_int == 6:  # Evaluación Preparación para crecer 2026
            logger.info("🎯 SAVE_ASSESSMENT: Using calculate_growth_preparation_score function")
            score, result_text, dimensional_scores = calculate_growth_preparation_score(responses)
        elif assessment_id_int == 1:  # Evaluación de Asertividad
            logger.info(f"🎯 SAVE_ASSESSMENT: Using calculate_assertiveness_score function")
            score, result_text, dimensional_scores = calculate_assertiveness_score(responses)
        else:  # Evaluaciones personalizadas creadas por coaches
            logger.info(f"🎯 SAVE_ASSESSMENT: Using calculate_custom_assessment_score for assessment_id={assessment_id_int}")
            score, result_text, dimensional_scores = calculate_custom_assessment_score(responses, assessment_id_int)
        
        # Determinar número de respuestas
        num_responses = len(responses) if isinstance(responses, list) else len(responses)
        
        # MEJORADO: Implementar upsert logic para evitar race conditions
        assessment_result = None
        existing_result = None
        
        try:
            # Buscar resultado existente
            existing_result = AssessmentResult.query.filter_by(
                user_id=current_coachee.id,
                assessment_id=assessment_id_int
            ).first()
            
            if existing_result:
                logger.info(f"SAVE_ASSESSMENT: Actualizando resultado existente para usuario {current_coachee.id} y evaluación {assessment_id_int}")
                
                # Actualizar historial de puntajes ANTES de actualizar el puntaje principal
                total_attempts = update_score_history(existing_result, score)
                logger.info(f"SAVE_ASSESSMENT: Intento #{total_attempts} registrado en historial")
                
                # Actualizar el resultado existente
                existing_result.score = score
                existing_result.total_questions = num_responses
                existing_result.result_text = result_text
                existing_result.dimensional_scores = dimensional_scores
                existing_result.completed_at = datetime.utcnow()
                
                # Actualizar coach si es necesario
                if current_coachee.coach_id:
                    existing_result.coach_id = current_coachee.coach_id
                    
                assessment_result = existing_result  # Para usar en el resto del código
                
                # Eliminar respuestas anteriores para este resultado
                Response.query.filter_by(assessment_result_id=assessment_result.id).delete()
                logger.info(f"SAVE_ASSESSMENT: Eliminadas respuestas anteriores para resultado {assessment_result.id}")
                
            else:
                # Crear resultado de evaluación nuevo
                assessment_result = AssessmentResult(
                    user_id=current_coachee.id,
                    assessment_id=assessment_id_int,
                    score=score,
                    total_questions=num_responses,
                    result_text=result_text,
                    dimensional_scores=dimensional_scores,
                    score_history=[]  # Inicializar historial vacío
                )
                
                # Agregar el primer intento al historial
                update_score_history(assessment_result, score)
                logger.info(f"SAVE_ASSESSMENT: Primer intento registrado en historial para nueva evaluación")
                
                # Si hay coach asignado
                if current_coachee.coach_id:
                    assessment_result.coach_id = current_coachee.coach_id
                
                db.session.add(assessment_result)
                
            # Hacer flush aquí, FUERA del if/else, para ambos casos
            db.session.flush()
            logger.info(f"SAVE_ASSESSMENT: Flush exitoso - resultado ID {assessment_result.id}")
                
        except Exception as query_error:
            logger.error(f"❌ SAVE_ASSESSMENT: Error en query inicial: {str(query_error)}")
            logger.error(f"❌ SAVE_ASSESSMENT: Error type: {type(query_error).__name__}")
            logger.error(f"❌ SAVE_ASSESSMENT: Traceback: {traceback.format_exc()}")
            db.session.rollback()
            
            # No retornar error aquí - intentar continuar con retry logic
            # El error será manejado en el commit final
            logger.warning(f"⚠️ SAVE_ASSESSMENT: Attempting to continue despite flush error")
            
            # Intentar recuperar el assessment_result si existe
            try:
                assessment_result = AssessmentResult.query.filter_by(
                    user_id=current_coachee.id,
                    assessment_id=assessment_id_int
                ).first()
                
                if not assessment_result:
                    # Si definitivamente no existe, retornar error
                    return jsonify({
                        'success': False,
                        'error': 'Error en consulta de base de datos. Por favor, intenta nuevamente.',
                        'code': 'DATABASE_QUERY_ERROR'
                    }), 500
                    
                logger.info(f"✅ SAVE_ASSESSMENT: Recuperado assessment_result existente ID {assessment_result.id}")
            except Exception as recovery_error:
                logger.error(f"❌ SAVE_ASSESSMENT: No se pudo recuperar assessment_result: {str(recovery_error)}")
                return jsonify({
                    'success': False,
                    'error': 'Error en consulta de base de datos. Por favor, intenta nuevamente.',
                    'code': 'DATABASE_QUERY_ERROR'
                }), 500
        
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
        
        # Intentar commit con manejo robusto de errores UNIQUE constraint
        try:
            db.session.commit()
            logger.info(f"✅ SAVE_ASSESSMENT: Successfully saved assessment result ID {assessment_result.id} for user {current_coachee.username}")
            
        except Exception as commit_error:
            db.session.rollback()
            error_str = str(commit_error)
            
            # Manejar específicamente errores de UNIQUE constraint (SQLite y PostgreSQL)
            if "UNIQUE constraint failed" in error_str or "IntegrityError" in error_str or "UniqueViolation" in error_str or "duplicate key value" in error_str:
                logger.warning(f"⚠️ SAVE_ASSESSMENT: UNIQUE constraint detected - attempting recovery")
                logger.warning(f"⚠️ SAVE_ASSESSMENT: Error details: {error_str}")
                
                try:
                    # Intentar recovery: buscar el resultado existente y actualizarlo
                    recovery_result = AssessmentResult.query.filter_by(
                        user_id=current_coachee.id,
                        assessment_id=assessment_id_int
                    ).first()
                    
                    if recovery_result:
                        logger.info(f"✅ SAVE_ASSESSMENT: Found existing result during recovery - updating it")
                        
                        # Actualizar historial de puntajes
                        total_attempts = update_score_history(recovery_result, score)
                        logger.info(f"SAVE_ASSESSMENT: Recovery - Intento #{total_attempts} registrado")
                        
                        # Actualizar todos los campos
                        recovery_result.score = score
                        recovery_result.total_questions = num_responses
                        recovery_result.result_text = result_text
                        recovery_result.dimensional_scores = dimensional_scores
                        recovery_result.completed_at = datetime.utcnow()
                        
                        if current_coachee.coach_id:
                            recovery_result.coach_id = current_coachee.coach_id
                        
                        # Eliminar respuestas anteriores y agregar las nuevas
                        Response.query.filter_by(assessment_result_id=recovery_result.id).delete()
                        
                        # Agregar respuestas nuevas
                        if isinstance(responses, list):
                            for response_data in responses:
                                response = Response(
                                    user_id=current_coachee.id,
                                    question_id=int(response_data['question_id']),
                                    selected_option=int(response_data['selected_option']),
                                    assessment_result_id=recovery_result.id
                                )
                                db.session.add(response)
                        else:
                            for question_id, selected_option in responses.items():
                                response = Response(
                                    user_id=current_coachee.id,
                                    question_id=int(question_id),
                                    selected_option=int(selected_option),
                                    assessment_result_id=recovery_result.id
                                )
                                db.session.add(response)
                        
                        # Intentar commit de recovery
                        db.session.commit()
                        assessment_result = recovery_result
                        logger.info(f"✅ SAVE_ASSESSMENT: Recovery successful - result ID {assessment_result.id}")
                        
                    else:
                        logger.error(f"❌ SAVE_ASSESSMENT: Recovery failed - no existing result found")
                        return jsonify({
                            'success': False,
                            'error': 'Error de concurrencia al guardar evaluación. Por favor, recarga la página e intenta nuevamente.',
                            'code': 'CONCURRENCY_ERROR'
                        }), 409
                        
                except Exception as recovery_error:
                    db.session.rollback()
                    logger.error(f"❌ SAVE_ASSESSMENT: Recovery failed: {str(recovery_error)}")
                    return jsonify({
                        'success': False,
                        'error': 'Ya has completado esta evaluación previamente. Por favor, recarga la página.',
                        'code': 'DUPLICATE_ASSESSMENT'
                    }), 409
                    
            else:
                # Error diferente a UNIQUE constraint
                logger.error(f"❌ SAVE_ASSESSMENT: Unexpected commit error: {error_str}")
                return jsonify({
                    'success': False,
                    'error': f'Error guardando evaluación: {error_str}',
                    'code': 'COMMIT_ERROR'
                }), 500
        
        # Crear notificación para el coach si existe
        if current_coachee.coach_id:
            assessment = Assessment.query.get(assessment_id_int)
            assessment_name = assessment.title if assessment else 'una evaluación'
            create_notification(
                user_id=current_coachee.coach_id,
                type='evaluation_completed',
                title='Evaluación completada',
                message=f'{current_coachee.full_name} ha completado {assessment_name}',
                related_id=assessment_result.id,
                related_type='assessment_result'
            )
        
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
@coach_session_required
def coach_dashboard():
    """Ruta principal del dashboard - Redirige a dashboard v2"""
    return redirect(url_for('coach_dashboard_v2'))

@app.route('/coach/dashboard-v2')
@coach_session_required
def coach_dashboard_v2():
    """Dashboard V2 reescrito completamente en Alpine.js - Mantiene todas las funcionalidades del original"""
    current_coach = g.current_user
    
    # Validar que el usuario esté autenticado
    if not current_coach or not hasattr(current_coach, 'id'):
        logger.warning("⚠️ Intento de acceso a dashboard sin autenticación válida")
        session.clear()
        flash('Tu sesión ha expirado. Por favor, inicia sesión nuevamente.', 'warning')
        return redirect(url_for('coach_login_page'))
    
    # Validar timeout de actividad (2 horas)
    last_activity = session.get('last_activity_coach')
    if last_activity:
        from datetime import datetime, timedelta
        try:
            last_activity_time = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_activity_time > timedelta(hours=2):
                logger.info(f"⏰ Sesión de coach expirada por inactividad (ID: {current_coach.id})")
                logout_user()
                session.clear()
                flash('Tu sesión ha expirado por inactividad. Por favor, inicia sesión nuevamente.', 'warning')
                return redirect(url_for('coach_login_page'))
        except:
            pass
    
    # Actualizar timestamp de actividad
    session['last_activity_coach'] = datetime.utcnow().isoformat()
    
    logger.info(f"✨ Coach dashboard v2 (Alpine.js) accessed by: {current_coach.username} (ID: {current_coach.id})")
    
    # Generar timestamp para forzar reload
    deploy_version = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    
    response = make_response(render_template('coach_dashboard_v2.html',
                         coach_name=current_coach.full_name or current_coach.username,
                         coach_email=current_coach.email,
                         coach_id=current_coach.id,
                         coach_avatar_url=current_coach.avatar_url or '/static/img/default-avatar.png',
                         deploy_version=deploy_version))
    
    # Prevenir cacheo del HTML para forzar actualizaciones
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Version'] = deploy_version
    response.headers['ETag'] = f'"{deploy_version}"'
    response.headers['Vary'] = 'Accept-Encoding'
    
    # Agregar CSP para permitir recursos externos (avatares, Chart.js, estilos CDN)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "style-src-elem 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https: http: blob:; "  # Permite imágenes de cualquier origen HTTPS/HTTP y blob para Chart.js
        "connect-src 'self' https: https://www.youtube.com https://www.instagram.com; "  # Permitir YouTube/Instagram oEmbed API
        "frame-src 'self' https://www.youtube.com https://youtube.com https://www.instagram.com https://instagram.com; "  # Permitir embeds de YouTube e Instagram
        "worker-src 'self' blob:; "  # Permite Web Workers para Chart.js
        "child-src 'self' blob:;"  # Soporte legacy para workers
    )
    
    # Agregar headers de cache control para prevenir acceso con botón atrás
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    
    return response

@app.route('/coach-feed')
@coach_session_required
def coach_feed():
    return render_template('coach_feed.html')

@app.route('/coach-comunidad')
@coach_session_required
def coach_comunidad():
    return render_template('coach_comunidad.html')

@app.route('/coach-profile')
@coach_session_required
def coach_profile():
    return render_template('coach_profile.html')

@app.route('/coachee-dashboard')
@coachee_session_required
def coachee_dashboard():
    # ✨ NUEVO: Detectar si viene de invitación y pasar assessment_id al template
    auto_start_assessment = None
    if session.get('first_login') and session.get('target_assessment_id'):
        auto_start_assessment = session.pop('target_assessment_id')
        session.pop('first_login')
    
    return render_template('coachee_dashboard.html', auto_start_assessment=auto_start_assessment)

@app.route('/coachee-feed')
@coachee_session_required
def coachee_feed():
    return render_template('coachee_feed.html')

@app.route('/coachee-profile')
@coachee_session_required
def coachee_profile():
    return render_template('coachee_profile.html')

@app.route('/platform-admin-dashboard')
@admin_required
def platform_admin_dashboard():
    # Validar sesión activa de admin con múltiples verificaciones
    if not current_user.is_authenticated:
        logger.warning("Intento de acceso a admin dashboard sin autenticación")
        session.clear()  # Limpiar cualquier resto de sesión
        flash('Tu sesión ha expirado. Por favor inicia sesión nuevamente.', 'warning')
        return redirect(url_for('admin_login_page'))
    
    if current_user.role != 'platform_admin':
        logger.warning(f"Usuario {current_user.username} (role: {current_user.role}) intentó acceder a admin dashboard")
        return redirect(url_for('dashboard_selection'))
    
    # Verificar que el timestamp de actividad no esté expirado
    last_activity = session.get('last_activity_admin')
    if last_activity:
        try:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_time > timedelta(hours=2):
                logger.warning(f"Sesión de admin expirada por inactividad: {current_user.username}")
                logout_user()
                session.clear()
                flash('Tu sesión ha expirado por inactividad.', 'warning')
                return redirect(url_for('admin_login_page'))
        except (ValueError, TypeError):
            pass
    
    # Inicializar o actualizar timestamp de actividad
    session['last_activity_admin'] = datetime.utcnow().isoformat()
    
    # Agregar headers anti-cache
    response = make_response(render_template('admin_dashboard.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/admin-dashboard')
def admin_dashboard():
    """Redirección al dashboard Alpine para compatibilidad"""
    return redirect('/admin/dashboard-alpine')

@app.route('/admin/dashboard-alpine')
@admin_required
def admin_dashboard_alpine():
    """Versión experimental del dashboard de administración usando Alpine.js"""
    # Validar sesión activa de admin
    if not current_user.is_authenticated:
        logger.warning("Intento de acceso a admin dashboard alpine sin autenticación")
        flash('Tu sesión ha expirado. Por favor inicia sesión nuevamente.', 'warning')
        return redirect(url_for('admin_login_page'))
    
    if current_user.role != 'platform_admin':
        logger.warning(f"Usuario {current_user.username} (role: {current_user.role}) intentó acceder a admin dashboard alpine")
        return redirect(url_for('dashboard_selection'))
    
    # Inicializar timestamp de actividad si no existe
    if 'last_activity_admin' not in session:
        session['last_activity_admin'] = datetime.utcnow().isoformat()
    
    return render_template('admin_dashboard_alpine.html')

@app.route('/admin/users-management')
@admin_required
def admin_users_management():
    """Panel de gestión completa de usuarios (coaches y coachees)"""
    # Validar sesión activa de admin
    if not current_user.is_authenticated:
        logger.warning("Intento de acceso a users management sin autenticación")
        flash('Tu sesión ha expirado. Por favor inicia sesión nuevamente.', 'warning')
        return redirect(url_for('admin_login_page'))
    
    if current_user.role != 'platform_admin':
        logger.warning(f"Usuario {current_user.username} (role: {current_user.role}) intentó acceder a users management")
        return redirect(url_for('dashboard_selection'))
    
    return render_template('admin_users_management.html')



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
        initial_session_id = data.get('initial_session_id')  # Sesión inicial del coachee
        
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
        
        # Generar username único basado en el nombre completo
        # Estrategia: 
        # 1. Intentar con primer nombre (en minúsculas, sin espacios)
        # 2. Si existe, intentar con nombre + apellido (en minúsculas, sin espacios)
        # 3. Si aún existe, agregar contador numérico
        
        name_parts = full_name.strip().split()
        first_name = name_parts[0].lower().replace(' ', '')
        
        # Intentar primero solo con el nombre
        username = first_name
        logger.info(f"🔤 INVITATION: Trying username: {username}")
        
        # Si el nombre ya existe, intentar con nombre + apellido
        if User.query.filter_by(username=username).first():
            if len(name_parts) > 1:
                # Combinar nombre y apellido
                last_name = name_parts[-1].lower().replace(' ', '')
                username = f"{first_name}{last_name}"
                logger.info(f"🔤 INVITATION: First name taken, trying: {username}")
            
            # Si aún existe (o no hay apellido), agregar contador
            counter = 1
            base_username = username
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
                logger.info(f"🔤 INVITATION: Still taken, trying: {username}")
        
        # Generar contraseña segura
        password_chars = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(password_chars) for _ in range(8))
        
        # Generar token único para invitación
        invite_token = secrets.token_urlsafe(32)
        logger.info(f"🔑 INVITATION: Generated secure token for invitation")
        
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
        db.session.flush()  # Obtener ID sin hacer commit completo
        
        # Crear registro de invitación
        invitation = Invitation(
            coach_id=current_coach.id,
            coachee_id=new_coachee.id,
            email=email,
            full_name=full_name,
            token=invite_token,
            message=message,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            status='pending'
        )
        db.session.add(invitation)
        db.session.commit()
        logger.info(f"✅ INVITATION: Invitation created with status 'pending'")
        
        logger.info(f"✅ INVITATION: Invitation record created with token for coachee {new_coachee.id}")
        
        # Verificar que se creó correctamente
        logger.info(f"✅ INVITATION: Coachee {full_name} created successfully with ID {new_coachee.id}")
        logger.info(f"✅ INVITATION: Verification - Coach ID: {new_coachee.coach_id}, Role: {new_coachee.role}")
        
        # Verificar que se puede encontrar en consulta
        verification_query = User.query.filter_by(coach_id=current_coach.id, role='coachee').all()
        logger.info(f"🔍 INVITATION: Post-creation verification - Found {len(verification_query)} coachees for coach {current_coach.id}")
        for v_coachee in verification_query:
            logger.info(f"🔍 INVITATION: Verification coachee: ID={v_coachee.id}, Name={v_coachee.full_name}, Coach_ID={v_coachee.coach_id}")
        
        # Agregar coachee como participante de la sesión inicial si se especificó
        session_name_assigned = None
        if initial_session_id is not None:
            try:
                session_rec = SessionRecord.query.filter_by(
                    session_number=int(initial_session_id), coach_id=current_coach.id
                ).first()
                if session_rec:
                    current_participants = json.loads(session_rec.participants) if session_rec.participants else []
                    if new_coachee.id not in current_participants:
                        current_participants.append(new_coachee.id)
                        session_rec.participants = json.dumps(current_participants)
                        db.session.commit()
                    session_name_assigned = session_rec.name
                    logger.info(f"✅ INVITATION: Coachee {new_coachee.id} agregado a sesión '{session_rec.name}'")
            except Exception as se:
                logger.warning(f"⚠️ INVITATION: No se pudo asignar sesión inicial: {se}")

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
                        # Vincular assessment a invitación
                        invitation.assessment_id = assessment.id
                        db.session.add(invitation)
                        
                        # Crear una tarea de evaluación para el coachee
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
                            logger.info(f"✅ INVITATION: Assessment '{assessment.title}' linked to invitation and task (Task ID: {new_task.id})")
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
        
        # Construir URL de invitación con token
        invitation_url = f"{request.url_root}invite/{invite_token}"
        
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
                'invitation_url': invitation_url,  # Nueva URL con token
                'login_url': f"{request.url_root}participant-access",  # Backup
                'assigned_assessment': assigned_assessment_title if assessment_assigned else None,
                'initial_session': session_name_assigned
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ INVITATION: Error creating coachee: {str(e)}")
        return jsonify({'error': f'Error creando coachee: {str(e)}'}), 500

@app.route('/api/coach/dashboard-init', methods=['GET'])
@coach_session_required
def api_coach_dashboard_init():
    """
    Endpoint optimizado que retorna TODOS los datos necesarios para inicializar el dashboard
    en una sola llamada, reduciendo latencia de red en producción.
    
    Retorna:
    - profile: Datos del perfil del coach
    - stats: Estadísticas del dashboard
    - coachees: Lista de coachees (limitada a primeros 50)
    - recent_activity: Actividad reciente
    """
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        logger.info(f"🚀 DASHBOARD-INIT: Loading all data for coach {current_coach.username}")
        
        # 1. PROFILE DATA
        profile_data = {
            'id': current_coach.id,
            'username': current_coach.username,
            'email': current_coach.email,
            'full_name': current_coach.full_name or current_coach.username,
            'avatar_url': current_coach.avatar_url
        }
        
        # 2. COACHEES DATA (limitado a 50 para velocidad)
        coachees = User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).limit(50).all()
        
        coachee_ids = [c.id for c in coachees]
        
        # Optimización: Queries agrupadas
        evaluations_counts = {}
        if coachee_ids:
            eval_counts_result = db.session.query(
                AssessmentResult.user_id,
                func.count(AssessmentResult.id)
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids)
            ).group_by(AssessmentResult.user_id).all()
            evaluations_counts = {user_id: count for user_id, count in eval_counts_result}
        
        avg_scores = {}
        if coachee_ids:
            avg_scores_result = db.session.query(
                AssessmentResult.user_id,
                func.avg(AssessmentResult.score)
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids),
                AssessmentResult.score.isnot(None)
            ).group_by(AssessmentResult.user_id).all()
            avg_scores = {user_id: round(float(avg), 1) for user_id, avg in avg_scores_result if avg is not None}
        
        # Formatear coachees
        coachees_data = []
        for coachee in coachees:
            coachee_data = {
                'id': coachee.id,
                'username': coachee.username,
                'email': coachee.email,
                'full_name': coachee.full_name or coachee.username,
                'avatar_url': coachee.avatar_url,
                'evaluations_count': evaluations_counts.get(coachee.id, 0),
                'avg_score': avg_scores.get(coachee.id, 0)
            }
            coachees_data.append(coachee_data)
        
        # 3. STATS DATA
        total_coachees = User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).count()
        
        # Contar tareas de evaluación asignadas
        total_assigned_tasks = Task.query.filter_by(
            coach_id=current_coach.id,
            category='evaluation',
            is_active=True
        ).count()
        
        completed_assessments = sum(evaluations_counts.values()) if evaluations_counts else 0
        
        # Promedio general
        avg_score_result = db.session.query(
            func.avg(AssessmentResult.score)
        ).filter(
            AssessmentResult.user_id.in_(coachee_ids),
            AssessmentResult.score.isnot(None)
        ).scalar() if coachee_ids else None
        average_score = round(float(avg_score_result), 1) if avg_score_result else 0
        
        # Contenido publicado
        published_content = Content.query.filter_by(
            coach_id=current_coach.id,
            is_active=True
        ).count()
        
        # Sesiones programadas
        from datetime import date
        today = date.today()
        scheduled_sessions = CoachingSession.query.filter(
            CoachingSession.coach_id == current_coach.id,
            CoachingSession.status.in_(['pending', 'confirmed']),
            CoachingSession.session_date >= today
        ).count()
        
        # Compromisos creados (desde registros de sesión)
        total_commitments = 0
        commitments_completed = 0
        commitments_partial = 0
        commitments_pending = 0
        session_records = SessionRecord.query.filter_by(coach_id=current_coach.id).all()
        for sr in session_records:
            if sr.commitments:
                try:
                    comms = json.loads(sr.commitments)
                    if isinstance(comms, list):
                        total_commitments += len(comms)
                        for c in comms:
                            st = c.get('status', 'pendiente') if isinstance(c, dict) else 'pendiente'
                            if st == 'completado':
                                commitments_completed += 1
                            elif st == 'parcial':
                                commitments_partial += 1
                            else:
                                commitments_pending += 1
                except:
                    pass

        stats_data = {
            'total_coachees': total_coachees,
            'completed_assessments': completed_assessments,
            'pending_assessments': max(0, total_assigned_tasks - completed_assessments),
            'average_score': average_score,
            'published_content': published_content,
            'scheduled_sessions': scheduled_sessions,
            'assigned_evaluation_tasks': total_assigned_tasks,
            'total_commitments': total_commitments,
            'commitments_completed': commitments_completed,
            'commitments_partial': commitments_partial,
            'commitments_pending': commitments_pending
        }
        
        # 4. RESPONSE COMBINADA
        response = {
            'success': True,
            'profile': profile_data,
            'coachees': coachees_data,
            'stats': stats_data,
            'coachees_total': total_coachees,
            'coachees_loaded': len(coachees_data)
        }
        
        logger.info(f"✅ DASHBOARD-INIT: Returning all data in single response")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"❌ DASHBOARD-INIT: Error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/coach/stats', methods=['GET'])
def api_coach_stats():
    """Obtener estadísticas del coach para el dashboard v2.0"""
    try:
        # Verificar si hay sesión de coach
        coach_user_id = session.get('coach_user_id')
        
        # Si no hay sesión, retornar stats vacías (modo demo)
        if not coach_user_id:
            logger.info("📊 STATS: No coach session, returning empty stats (demo mode)")
            return jsonify({
                'total_coachees': 0,
                'completed_assessments': 0,
                'pending_assessments': 0,
                'average_score': 0
            }), 200
        
        # Obtener coach actual
        current_coach = User.query.get(coach_user_id)
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"⚠️ STATS: Invalid coach user {coach_user_id}")
            return jsonify({
                'total_coachees': 0,
                'completed_assessments': 0,
                'pending_assessments': 0,
                'average_score': 0
            }), 200
        
        logger.info(f"📊 STATS: Calculating stats for coach {current_coach.username} (ID: {current_coach.id})")
        
        # Total de coachees
        total_coachees = User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).count()
        
        # Obtener IDs de coachees
        coachee_ids = [c.id for c in User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).with_entities(User.id).all()]
        
        # Evaluaciones completadas
        completed_assessments = AssessmentResult.query.filter(
            AssessmentResult.user_id.in_(coachee_ids)
        ).count() if coachee_ids else 0
        
        # Evaluaciones pendientes (tareas de evaluación activas)
        pending_assessments = Task.query.filter_by(
            coach_id=current_coach.id,
            category='evaluation',
            is_active=True
        ).filter(
            Task.coachee_id.in_(coachee_ids)
        ).filter(
            ~Task.id.in_(
                db.session.query(AssessmentResult.id).filter(
                    AssessmentResult.user_id.in_(coachee_ids)
                )
            )
        ).count() if coachee_ids else 0
        
        # Promedio general de scores
        avg_score_result = db.session.query(
            func.avg(AssessmentResult.score)
        ).filter(
            AssessmentResult.user_id.in_(coachee_ids),
            AssessmentResult.score.isnot(None)
        ).scalar() if coachee_ids else None
        
        average_score = round(float(avg_score_result), 1) if avg_score_result else 0
        
        # Contenido publicado (videos, documentos, artículos de la tabla Content)
        published_content = Content.query.filter_by(
            coach_id=current_coach.id,
            is_active=True
        ).count()
        
        # Sesiones programadas (sesiones confirmadas o pendientes en el futuro)
        from datetime import date
        today = date.today()
        scheduled_sessions = CoachingSession.query.filter(
            CoachingSession.coach_id == current_coach.id,
            CoachingSession.status.in_(['pending', 'confirmed']),
            CoachingSession.session_date >= today
        ).count()
        
        stats = {
            'total_coachees': total_coachees,
            'completed_assessments': completed_assessments,
            'pending_assessments': pending_assessments,
            'average_score': average_score,
            'published_content': published_content,
            'scheduled_sessions': scheduled_sessions
        }
        
        logger.info(f"✅ STATS: Returning stats: {stats}")
        return jsonify(stats), 200
        
    except Exception as e:
        logger.error(f"❌ STATS: Error calculating stats: {str(e)}")
        return jsonify({
            'total_coachees': 0,
            'completed_assessments': 0,
            'pending_assessments': 0,
            'average_score': 0
        }), 200

@app.route('/api/coach/overview-charts', methods=['GET'])
def api_coach_overview_charts():
    """Obtener datos para los gráficos del overview"""
    try:
        coach_user_id = session.get('coach_user_id')
        
        if not coach_user_id:
            logger.info("📊 OVERVIEW-CHARTS: No coach session, returning demo data")
            return jsonify({
                'activity_chart': {'labels': [], 'data': []},
                'content_type_chart': {'labels': [], 'data': []},
                'evaluations_chart': {'labels': [], 'data': []}
            }), 200
        
        current_coach = User.query.get(coach_user_id)
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"⚠️ OVERVIEW-CHARTS: Invalid coach user {coach_user_id}")
            return jsonify({
                'activity_chart': {'labels': [], 'data': []},
                'content_type_chart': {'labels': [], 'data': []},
                'evaluations_chart': {'labels': [], 'data': []}
            }), 200
        
        logger.info(f"📊 OVERVIEW-CHARTS: Generating charts for coach {current_coach.username}")
        
        # 1. Activity Chart - Coachees activos por semana (últimas 4 semanas)
        from datetime import datetime, timedelta
        now = datetime.now()
        weeks_data = []
        weeks_labels = []
        
        for i in range(3, -1, -1):  # 4 semanas atrás hasta ahora
            week_start = now - timedelta(weeks=i+1)
            week_end = now - timedelta(weeks=i)
            weeks_labels.append(f'Sem {4-i}')
            
            # Contar coachees con actividad en esa semana
            active_coachees = User.query.filter(
                User.coach_id == current_coach.id,
                User.role == 'coachee',
                User.last_login >= week_start,
                User.last_login < week_end
            ).count()
            weeks_data.append(active_coachees)
        
        # 2. Content Type Chart - Distribución de tipos de contenido
        # Contar contenido publicado de la tabla Content por tipo
        video_count = Content.query.filter(
            Content.coach_id == current_coach.id,
            Content.content_type == 'video',
            Content.is_active == True
        ).count()
        
        document_count = Content.query.filter(
            Content.coach_id == current_coach.id,
            Content.content_type == 'document',
            Content.is_active == True
        ).count()
        
        article_count = Content.query.filter(
            Content.coach_id == current_coach.id,
            Content.content_type == 'article',
            Content.is_active == True
        ).count()
        
        total_content = video_count + document_count + article_count
        
        if total_content > 0:
            content_labels = ['Videos', 'Documentos', 'Artículos']
            content_data = [video_count, document_count, article_count]
        else:
            content_labels = []
            content_data = []
        
        # 3. Evaluations Chart - Evaluaciones completadas por mes (últimos 6 meses)
        # Obtener IDs de coachees para filtrar evaluaciones
        coachee_ids = [c.id for c in User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).with_entities(User.id).all()]
        
        months_data = []
        months_labels = []
        
        for i in range(5, -1, -1):  # 6 meses atrás hasta ahora
            month_date = now - timedelta(days=30*i)
            month_start = month_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            if i == 0:
                month_end = now
            else:
                next_month = month_start + timedelta(days=32)
                month_end = next_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Nombre del mes en español
            month_names = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic']
            months_labels.append(month_names[month_start.month - 1])
            
            # Contar evaluaciones completadas en ese mes
            if coachee_ids:
                completed = AssessmentResult.query.filter(
                    AssessmentResult.user_id.in_(coachee_ids),
                    AssessmentResult.completed_at >= month_start,
                    AssessmentResult.completed_at < month_end
                ).count()
                months_data.append(completed)
            else:
                months_data.append(0)
        
        result = {
            'activity_chart': {
                'labels': weeks_labels,
                'data': weeks_data
            },
            'content_type_chart': {
                'labels': content_labels,
                'data': content_data
            },
            'evaluations_chart': {
                'labels': months_labels,
                'data': months_data
            }
        }
        
        logger.info(f"✅ OVERVIEW-CHARTS: Returning chart data")
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"❌ OVERVIEW-CHARTS: Error: {str(e)}", exc_info=True)
        return jsonify({
            'activity_chart': {'labels': [], 'data': []},
            'content_type_chart': {'labels': [], 'data': []},
            'evaluations_chart': {'labels': [], 'data': []}
        }), 200

@app.route('/api/coach/recent-activity', methods=['GET'])
def api_coach_recent_activity():
    """Obtener actividad reciente de coachees"""
    from datetime import datetime, timedelta
    
    try:
        coach_user_id = session.get('coach_user_id')
        
        if not coach_user_id:
            logger.info("📋 RECENT-ACTIVITY: No coach session, returning empty list")
            return jsonify({'activities': []}), 200
        
        current_coach = User.query.get(coach_user_id)
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"⚠️ RECENT-ACTIVITY: Invalid coach user {coach_user_id}")
            return jsonify({'activities': []}), 200
        
        logger.info(f"📋 RECENT-ACTIVITY: Loading activity for coach {current_coach.username}")
        
        # Obtener IDs de coachees
        coachee_ids = [c.id for c in User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).with_entities(User.id).all()]
        
        logger.info(f"📋 RECENT-ACTIVITY: Found {len(coachee_ids)} coachees: {coachee_ids}")
        
        activities = []
        
        if coachee_ids:
            # 1. Evaluaciones completadas recientemente (últimas 10)
            recent_assessments = db.session.query(
                AssessmentResult, User, Assessment
            ).join(
                User, AssessmentResult.user_id == User.id
            ).join(
                Assessment, AssessmentResult.assessment_id == Assessment.id
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids)
            ).order_by(
                AssessmentResult.completed_at.desc()
            ).limit(10).all()
            
            logger.info(f"📋 RECENT-ACTIVITY: Found {len(recent_assessments)} recent assessments")
            
            for result, coachee, assessment in recent_assessments:
                # Calcular tiempo transcurrido
                if result.completed_at:
                    time_diff = datetime.now() - result.completed_at
                    if time_diff.days > 0:
                        time_ago = f"hace {time_diff.days}d"
                    elif time_diff.seconds >= 3600:
                        hours = time_diff.seconds // 3600
                        time_ago = f"hace {hours}h"
                    else:
                        minutes = time_diff.seconds // 60
                        time_ago = f"hace {minutes}m"
                else:
                    time_ago = "Recientemente"
                
                # Obtener iniciales
                name_parts = coachee.full_name.split() if coachee.full_name else ['?', '?']
                initials = ''.join([p[0].upper() for p in name_parts[:2]])
                
                activities.append({
                    'type': 'assessment_completed',
                    'coachee_name': coachee.full_name or coachee.username,
                    'coachee_initials': initials,
                    'description': f'completó la evaluación {assessment.title}',
                    'time_ago': time_ago,
                    'timestamp': result.completed_at.isoformat() if result.completed_at else None
                })
            
            # 2. Nuevos registros de coachees (últimos 5)
            thirty_days_ago = datetime.now() - timedelta(days=30)
            
            new_coachees = User.query.filter(
                User.id.in_(coachee_ids),
                User.created_at >= thirty_days_ago
            ).order_by(
                User.created_at.desc()
            ).limit(5).all()
            
            logger.info(f"📋 RECENT-ACTIVITY: Found {len(new_coachees)} new coachees (last 30 days)")
            
            for coachee in new_coachees:
                # Calcular tiempo transcurrido
                if coachee.created_at:
                    time_diff = datetime.now() - coachee.created_at
                    if time_diff.days > 0:
                        time_ago = f"hace {time_diff.days}d"
                    elif time_diff.seconds >= 3600:
                        hours = time_diff.seconds // 3600
                        time_ago = f"hace {hours}h"
                    else:
                        minutes = time_diff.seconds // 60
                        time_ago = f"hace {minutes}m"
                else:
                    time_ago = "Recientemente"
                
                # Obtener iniciales
                name_parts = coachee.full_name.split() if coachee.full_name else ['?', '?']
                initials = ''.join([p[0].upper() for p in name_parts[:2]])
                
                activities.append({
                    'type': 'new_coachee',
                    'coachee_name': coachee.full_name or coachee.username,
                    'coachee_initials': initials,
                    'description': 'se registró como nuevo coachee',
                    'time_ago': time_ago,
                    'timestamp': coachee.created_at.isoformat() if coachee.created_at else None
                })
        
        # Ordenar por timestamp (más reciente primero)
        activities.sort(key=lambda x: x['timestamp'] or '', reverse=True)
        
        # Limitar a 15 actividades
        activities = activities[:15]
        
        logger.info(f"✅ RECENT-ACTIVITY: Returning {len(activities)} activities")
        return jsonify({'activities': activities}), 200
        
    except Exception as e:
        logger.error(f"❌ RECENT-ACTIVITY: Error: {str(e)}", exc_info=True)
        return jsonify({'activities': []}), 200

@app.route('/api/coach/coachees', methods=['GET'])
def api_coach_coachees():
    """Obtener lista simplificada de coachees para el dashboard v2.0"""
    try:
        # Verificar si hay sesión de coach
        coach_user_id = session.get('coach_user_id')
        
        # Si no hay sesión, retornar lista vacía (modo demo)
        if not coach_user_id:
            logger.info("📋 COACHEES: No coach session, returning empty list (demo mode)")
            return jsonify({'coachees': []}), 200
        
        # Obtener coach actual
        current_coach = User.query.get(coach_user_id)
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"⚠️ COACHEES: Invalid coach user {coach_user_id}")
            return jsonify({'coachees': []}), 200
        
        logger.info(f"📋 COACHEES: Loading coachees for coach {current_coach.username} (ID: {current_coach.id})")
        
        # Obtener coachees
        coachees = User.query.filter_by(
            coach_id=current_coach.id,
            role='coachee'
        ).all()
        
        coachees_data = []
        for coachee in coachees:
            # Contar evaluaciones completadas
            completed = AssessmentResult.query.filter_by(user_id=coachee.id).count()
            
            # Contar evaluaciones pendientes
            pending = Task.query.filter_by(
                coachee_id=coachee.id,
                category='evaluation',
                is_active=True
            ).count()
            
            # Última evaluación
            last_eval = AssessmentResult.query.filter_by(
                user_id=coachee.id
            ).order_by(AssessmentResult.completed_at.desc()).first()
            
            coachees_data.append({
                'id': coachee.id,
                'name': coachee.full_name or coachee.username,
                'email': coachee.email,
                'avatar_url': coachee.avatar_url,
                'completed_assessments': completed,
                'pending_assessments': pending,
                'last_access': coachee.last_login.isoformat() if coachee.last_login else None,
                'last_evaluation_date': last_eval.completed_at.isoformat() if last_eval else None
            })
        
        logger.info(f"✅ COACHEES: Returning {len(coachees_data)} coachees")
        return jsonify({'coachees': coachees_data}), 200
        
    except Exception as e:
        logger.error(f"❌ COACHEES: Error loading coachees: {str(e)}")
        return jsonify({'coachees': []}), 200

def is_coachee_active(coachee, last_evaluation):
    """Determina si un coachee está activo (actividad en último mes)"""
    from datetime import timedelta
    one_month_ago = datetime.now() - timedelta(days=30)
    
    # Verificar última evaluación
    if last_evaluation and last_evaluation.get('completed_at'):
        try:
            eval_date_str = last_evaluation['completed_at'].replace('Z', '+00:00')
            eval_date = datetime.fromisoformat(eval_date_str)
            if eval_date > one_month_ago:
                return True
        except (ValueError, AttributeError):
            pass
    
    # Verificar último login
    if coachee.last_login and coachee.last_login > one_month_ago:
        return True
    
    return False

@app.route('/api/coach/my-coachees', methods=['GET'])
@coach_session_required
def api_coach_my_coachees():
    """Obtener la lista de coachees del coach actual"""
    logger.info("="*80)
    logger.info("🔍 MY-COACHEES: ===== INICIO DE REQUEST =====")
    logger.info(f"🔍 MY-COACHEES: g object: {dir(g)}")
    logger.info(f"🔍 MY-COACHEES: hasattr(g, 'current_user'): {hasattr(g, 'current_user')}")
    
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        logger.info(f"🔍 MY-COACHEES: current_coach obtenido: {current_coach}")
        logger.info(f"🔍 MY-COACHEES: type(current_coach): {type(current_coach)}")
        
        logger.info(f"🔍 MY-COACHEES: Request from user {current_coach.username if current_coach else 'Unknown'} (ID: {current_coach.id if current_coach else 'Unknown'}, role: {current_coach.role if current_coach else 'Unknown'})")
        
        # Verificar que es un coach
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"❌ MY-COACHEES: Access denied for user {current_coach.username if current_coach else 'None'} (role: {current_coach.role if current_coach else 'Unknown'})")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver sus coachees.'}), 403
        
        # Obtener coachees del coach actual
        logger.info(f"🔍 MY-COACHEES: Querying coachees for coach_id={current_coach.id}")
        coachees = User.query.filter_by(coach_id=current_coach.id, role='coachee').all()
        logger.info(f"📊 MY-COACHEES: Found {len(coachees)} coachees")
        
        # Contar tareas de evaluación asignadas a todos los coachees
        total_assigned_tasks = Task.query.filter_by(
            coach_id=current_coach.id,
            category='evaluation',
            is_active=True
        ).count()
        logger.info(f"📊 MY-COACHEES: Found {total_assigned_tasks} assigned evaluation tasks")
        
        # Log de cada coachee encontrado
        for coachee in coachees:
            logger.info(f"👤 MY-COACHEES: Coachee found - ID: {coachee.id}, Username: {coachee.username}, Email: {coachee.email}, Full Name: {coachee.full_name}, Coach ID: {coachee.coach_id}")
        
        # OPTIMIZACIÓN: Precalcular conteos y última evaluación en queries agrupadas
        coachee_ids = [c.id for c in coachees]
        
        # Query agrupada para contar evaluaciones por coachee
        evaluations_counts = {}
        try:
            eval_counts_result = db.session.query(
                AssessmentResult.user_id,
                func.count(AssessmentResult.id)
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids)
            ).group_by(AssessmentResult.user_id).all()
            evaluations_counts = {user_id: count for user_id, count in eval_counts_result}
            logger.info(f"📊 MY-COACHEES: Loaded evaluation counts for {len(evaluations_counts)} coachees")
        except Exception as ec_error:
            logger.warning(f"⚠️ MY-COACHEES: Could not load evaluation counts: {str(ec_error)}")
        
        # Query agrupada para obtener promedios de scores
        avg_scores = {}
        try:
            avg_scores_result = db.session.query(
                AssessmentResult.user_id,
                func.avg(AssessmentResult.score)
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids),
                AssessmentResult.score.isnot(None)
            ).group_by(AssessmentResult.user_id).all()
            avg_scores = {user_id: round(float(avg), 1) for user_id, avg in avg_scores_result if avg is not None}
            logger.info(f"📊 MY-COACHEES: Loaded average scores for {len(avg_scores)} coachees")
        except Exception as as_error:
            logger.warning(f"⚠️ MY-COACHEES: Could not load average scores: {str(as_error)}")
        
        # Query para obtener la última evaluación de cada coachee usando subquery
        last_evaluations = {}
        try:
            # Subquery para obtener la fecha más reciente por usuario
            subq = db.session.query(
                AssessmentResult.user_id,
                func.max(AssessmentResult.completed_at).label('max_date')
            ).filter(
                AssessmentResult.user_id.in_(coachee_ids)
            ).group_by(AssessmentResult.user_id).subquery()
            
            # Query principal para obtener los datos completos de la última evaluación
            last_evals_result = db.session.query(AssessmentResult).join(
                subq,
                and_(
                    AssessmentResult.user_id == subq.c.user_id,
                    AssessmentResult.completed_at == subq.c.max_date
                )
            ).all()
            
            for eval_result in last_evals_result:
                last_evaluations[eval_result.user_id] = {
                    'id': eval_result.id,
                    'score': eval_result.score,
                    'completed_at': eval_result.completed_at.isoformat(),
                    'assessment_id': eval_result.assessment_id
                }
            logger.info(f"📊 MY-COACHEES: Loaded last evaluations for {len(last_evaluations)} coachees")
        except Exception as le_error:
            logger.warning(f"⚠️ MY-COACHEES: Could not load last evaluations: {str(le_error)}")
        
        # 🔥 Query para contar evaluaciones pendientes por coachee (NO completadas)
        # LÓGICA CORRECTA: Una evaluación está pendiente si está asignada (Task activa) 
        # pero NO tiene un AssessmentResult completado
        pending_evaluations_counts = {}
        try:
            for coachee_id in coachee_ids:
                # Obtener tareas de evaluación asignadas a este coachee
                assigned_tasks = Task.query.filter(
                    Task.coach_id == current_coach.id,
                    Task.coachee_id == coachee_id,
                    Task.category == 'evaluation',
                    Task.is_active == True
                ).all()
                
                pending_count = 0
                for task in assigned_tasks:
                    # Extraer assessment_id del título de la tarea
                    assessment_title_from_task = task.title.replace('Completar: ', '').replace('Evaluación: ', '').strip()
                    
                    # Buscar la evaluación correspondiente
                    matching_assessment = Assessment.query.filter(
                        Assessment.title == assessment_title_from_task,
                        Assessment.is_active == True
                    ).first()
                    
                    if matching_assessment:
                        # Verificar si tiene resultado completado
                        has_completed = AssessmentResult.query.filter(
                            AssessmentResult.user_id == coachee_id,
                            AssessmentResult.assessment_id == matching_assessment.id,
                            AssessmentResult.completed_at.isnot(None)
                        ).first()
                        
                        if not has_completed:
                            pending_count += 1
                
                pending_evaluations_counts[coachee_id] = pending_count
            
            logger.info(f"📊 MY-COACHEES: Loaded pending evaluations counts for {len(pending_evaluations_counts)} coachees")
        except Exception as pec_error:
            logger.warning(f"⚠️ MY-COACHEES: Could not load pending evaluations counts: {str(pec_error)}")
        
        # Construir respuesta usando datos precargados
        coachees_data = []
        for coachee in coachees:
            last_eval = last_evaluations.get(coachee.id)
            coachee_data = {
                'id': coachee.id,
                'username': coachee.username,
                'email': coachee.email,
                'full_name': coachee.full_name,
                'name': coachee.full_name,  # ✅ Agregar campo 'name' para compatibilidad
                'created_at': coachee.created_at.isoformat() if coachee.created_at else None,
                'is_active': is_coachee_active(coachee, last_eval),  # ✅ Estado de actividad calculado
                'account_active': coachee.is_active,  # ✅ Estado de cuenta (activo/desactivado)
                'evaluations_count': evaluations_counts.get(coachee.id, 0),
                'pending_evaluations_count': pending_evaluations_counts.get(coachee.id, 0),  # ✅ Contar evaluaciones pendientes
                'last_evaluation': last_eval,
                'avg_score': avg_scores.get(coachee.id),
                'password': coachee.original_password,  # ✅ Incluir contraseña original para que el coach pueda verla
                'avatar_url': coachee.avatar_url,  # ✅ Incluir URL del avatar
                'coach_notes': coachee.coach_notes,  # ✅ Incluir notas del coach
                'last_login': coachee.last_login.isoformat() if coachee.last_login else None  # ✅ Último login
            }
            coachees_data.append(coachee_data)
            logger.info(f"✅ MY-COACHEES: Processed coachee {coachee.full_name} with data: {coachee_data}")
        
        logger.info(f"📤 MY-COACHEES: Returning {len(coachees_data)} coachees in response")
        
        return jsonify({
            'success': True,
            'coachees': coachees_data,
            'total': len(coachees_data),
            'assigned_evaluation_tasks': total_assigned_tasks  # Total tareas de evaluación asignadas
        }), 200
        
    except Exception as e:
        # Logging super detallado del error
        logger.error("="*80)
        logger.error("❌ MY-COACHEES: ===== ERROR CAPTURADO =====")
        logger.error(f"❌ MY-COACHEES: Exception type: {type(e).__name__}")
        logger.error(f"❌ MY-COACHEES: Exception message: {str(e)}")
        logger.error(f"❌ MY-COACHEES: Exception args: {e.args}")
        
        # Usar current_coach en lugar de current_user
        current_coach = getattr(g, 'current_user', None)
        coach_info = f"{current_coach.username} (ID: {current_coach.id})" if current_coach else "Unknown"
        logger.error(f"❌ MY-COACHEES: Error getting coachees for coach {coach_info}: {str(e)}")
        logger.error(f"❌ MY-COACHEES: Exception details: {e.__class__.__name__}: {str(e)}")
        logger.error(f"❌ MY-COACHEES: Traceback: {traceback.format_exc()}")
        logger.error("="*80)
        return jsonify({'error': f'Error obteniendo coachees: {str(e)}'}), 500

@app.route('/api/coach/development-plan-requests', methods=['GET'])
@coach_session_required
def api_coach_development_plan_requests():
    """Obtener solicitudes de planes de desarrollo de los coachees"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        logger.info(f"🔍 DEV-PLAN-REQUESTS: Request from coach {current_coach.username} (ID: {current_coach.id})")
        
        # Obtener todas las solicitudes de planes de desarrollo
        requests_tasks = Task.query.filter_by(
            coach_id=current_coach.id,
            category='development_plan_request',
            is_active=True
        ).order_by(Task.created_at.desc()).all()
        
        logger.info(f"📊 DEV-PLAN-REQUESTS: Found {len(requests_tasks)} development plan requests")
        
        # Crear lista de solicitudes con información completa
        requests_list = []
        for task in requests_tasks:
            coachee = User.query.get(task.coachee_id)
            if coachee:
                requests_list.append({
                    'id': task.id,
                    'title': task.title,
                    'description': task.description,
                    'coachee_id': coachee.id,
                    'coachee_name': coachee.full_name or coachee.username,
                    'coachee_email': coachee.email,
                    'request_date': task.created_at.isoformat(),
                    'priority': task.priority or 'high',
                    'status': 'pending'
                })
        
        return jsonify({
            'success': True,
            'requests': requests_list
        })
        
    except Exception as e:
        logger.error(f"Error en api_coach_development_plan_requests: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/development-plan-request/<int:task_id>', methods=['GET'])
@coach_session_required
def api_coach_development_plan_request_detail(task_id):
    """Obtener detalles completos de una solicitud de plan de desarrollo"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Obtener la tarea
        task = Task.query.filter_by(
            id=task_id,
            coach_id=current_coach.id,
            category='development_plan_request'
        ).first()
        
        if not task:
            return jsonify({'error': 'Solicitud no encontrada'}), 404
        
        # Obtener información del coachee
        coachee = User.query.get(task.coachee_id)
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado'}), 404
        
        # Extraer metadata JSON de la descripción
        import re
        import json
        
        metadata = {}
        evaluation_id = None
        
        # Intentar extraer metadata JSON
        metadata_match = re.search(r'__METADATA__\n(.*?)\n__END_METADATA__', task.description, re.DOTALL)
        if metadata_match:
            try:
                metadata = json.loads(metadata_match.group(1))
                evaluation_id = metadata.get('evaluation_id')
                logger.info(f"✅ DEV-PLAN-DETAIL: Extracted metadata: {metadata}")
            except json.JSONDecodeError:
                logger.warning(f"⚠️ DEV-PLAN-DETAIL: Could not parse metadata JSON")
        
        # Fallback: buscar en formato antiguo
        if not evaluation_id:
            eval_id_match = re.search(r'Evaluación ID: (\d+)', task.description)
            evaluation_id = int(eval_id_match.group(1)) if eval_id_match else None
            logger.info(f"🔍 DEV-PLAN-DETAIL: Using fallback extraction, evaluation_id: {evaluation_id}")
            
            # Extraer focus_areas del formato antiguo
            focus_areas_section = re.search(r'Áreas de enfoque seleccionadas:\n((?:- .+\n?)+)', task.description)
            if focus_areas_section:
                focus_areas_text = focus_areas_section.group(1)
                metadata['focus_areas'] = [line.strip('- \n') for line in focus_areas_text.split('\n') if line.strip().startswith('-')]
                logger.info(f"🔍 DEV-PLAN-DETAIL: Extracted focus_areas from old format: {metadata['focus_areas']}")
            
            # Extraer goals del formato antiguo
            goals_match = re.search(r'Objetivos específicos:\n(.+?)(?:\n\n|$)', task.description, re.DOTALL)
            if goals_match:
                metadata['goals'] = goals_match.group(1).strip()
                logger.info(f"🔍 DEV-PLAN-DETAIL: Extracted goals from old format: {metadata['goals']}")
            
            # Extraer priority si está en el task.priority
            if task.priority:
                metadata['priority'] = task.priority
        
        logger.info(f"🔍 DEV-PLAN-DETAIL: Task description: {task.description}")
        logger.info(f"🔍 DEV-PLAN-DETAIL: Final evaluation_id: {evaluation_id}")
        logger.info(f"🔍 DEV-PLAN-DETAIL: Final metadata: {metadata}")
        
        evaluation_data = None
        if evaluation_id:
            # Obtener resultado de la evaluación
            evaluation = AssessmentResult.query.filter_by(
                id=evaluation_id,
                user_id=coachee.id
            ).first()
            
            logger.info(f"🔍 DEV-PLAN-DETAIL: Found evaluation: {evaluation is not None}")
            
            if evaluation:
                # Obtener información del assessment
                assessment = Assessment.query.get(evaluation.assessment_id)
                
                logger.info(f"✅ DEV-PLAN-DETAIL: Evaluation found - ID: {evaluation.id}, Score: {evaluation.score}, Assessment: {assessment.title if assessment else 'None'}")
                
                evaluation_data = {
                    'id': evaluation.id,
                    'assessment_id': evaluation.assessment_id,
                    'assessment_title': assessment.title if assessment else 'Evaluación',
                    'score': evaluation.score,
                    'completed_at': evaluation.completed_at.isoformat() if evaluation.completed_at else None
                }
            else:
                logger.warning(f"⚠️ DEV-PLAN-DETAIL: No evaluation found with ID {evaluation_id} for coachee {coachee.id}")
        else:
            logger.warning(f"⚠️ DEV-PLAN-DETAIL: Could not extract evaluation_id from description")
        
        # Extraer mensaje personalizado de la descripción (sin metadata)
        description_clean = re.sub(r'__METADATA__.*?__END_METADATA__', '', task.description, flags=re.DOTALL)
        description_lines = description_clean.split('\n')
        custom_message = ''
        for i, line in enumerate(description_lines):
            if i > 0 and not line.startswith('Evaluación ID:') and not line.startswith('Score:'):
                custom_message += line + '\n'
        custom_message = custom_message.strip()
        
        return jsonify({
            'success': True,
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'custom_message': custom_message,
                'created_at': task.created_at.isoformat(),
                'priority': task.priority
            },
            'coachee': {
                'id': coachee.id,
                'name': coachee.full_name or coachee.username,
                'email': coachee.email,
                'username': coachee.username
            },
            'evaluation': evaluation_data,
            'priority': metadata.get('priority', task.priority),
            'focus_areas': metadata.get('focus_areas', []),
            'goals': metadata.get('goals', '')
        })
        
    except Exception as e:
        logger.error(f"Error en api_coach_development_plan_request_detail: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/development-plan', methods=['POST'])
@coach_session_required
def api_coach_create_development_plan():
    """Crear un nuevo Plan de Desarrollo Personal"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        
        # Validar campos obligatorios
        if not data.get('objetivo'):
            return jsonify({'error': 'El objetivo es obligatorio'}), 400
        
        if not data.get('areas_desarrollo') or len(data.get('areas_desarrollo', [])) == 0:
            return jsonify({'error': 'Debe seleccionar al menos un área de desarrollo'}), 400
        
        if len(data.get('areas_desarrollo', [])) > 3:
            return jsonify({'error': 'Máximo 3 áreas de desarrollo'}), 400
        
        if not data.get('acciones') or len(data.get('acciones', [])) == 0:
            return jsonify({'error': 'Debe agregar al menos una acción'}), 400
        
        if not data.get('coachee_id'):
            return jsonify({'error': 'Debe especificar un coachee'}), 400
        
        # Verificar que el coachee pertenece al coach
        coachee = User.query.filter_by(
            id=data.get('coachee_id'),
            coach_id=current_coach.id
        ).first()
        
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no autorizado'}), 404
        
        # Crear el plan
        new_plan = DevelopmentPlan(
            coach_id=current_coach.id,
            coachee_id=coachee.id,
            request_task_id=data.get('request_task_id'),
            objetivo=data.get('objetivo'),
            situacion_actual=data.get('situacion_actual'),
            category=data.get('category', 'personal'),
            areas_desarrollo=data.get('areas_desarrollo'),
            acciones=data.get('acciones'),
            milestones=data.get('milestones', []),  # Hitos personalizados
            indicadores=data.get('indicadores'),
            status=data.get('status', 'draft')  # draft o published
        )
        
        if data.get('status') == 'published':
            new_plan.published_at = datetime.utcnow()
        
        db.session.add(new_plan)
        
        # Marcar la solicitud como completada si existe
        request_task_id = data.get('request_task_id')
        if request_task_id:
            request_task = Task.query.filter_by(
                id=request_task_id,
                coach_id=current_coach.id,
                category='development_plan_request'
            ).first()
            
            if request_task:
                request_task.is_active = False
                request_task.completed_date = datetime.utcnow()
                logger.info(f"✅ DEV-PLAN-REQUEST: Solicitud {request_task_id} marcada como completada")
        
        db.session.commit()
        
        logger.info(f"📋 DEV-PLAN-CREATE: Coach {current_coach.id} created plan {new_plan.id} for coachee {coachee.id}, status: {new_plan.status}")
        
        return jsonify({
            'success': True,
            'plan_id': new_plan.id,
            'status': new_plan.status,
            'message': 'Plan de desarrollo creado exitosamente' if new_plan.status == 'draft' else 'Plan de desarrollo publicado exitosamente'
        })
        
    except Exception as e:
        logger.error(f"Error en api_coach_create_development_plan: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/development-plan/<int:plan_id>', methods=['PUT'])
@coach_session_required
def api_coach_update_development_plan(plan_id):
    """Actualizar un plan de desarrollo existente"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"📝 COACH-UPDATE: Coach {current_coach.id if current_coach else 'None'} attempting to update plan {plan_id}")
        
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"⚠️ COACH-UPDATE: Access denied - user role: {current_coach.role if current_coach else 'None'}")
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        logger.info(f"📦 COACH-UPDATE: Received data - category: {data.get('category')}")
        
        # Buscar el plan
        plan = DevelopmentPlan.query.filter_by(
            id=plan_id,
            coach_id=current_coach.id
        ).first()
        
        if not plan:
            logger.warning(f"⚠️ COACH-UPDATE: Plan {plan_id} not found for coach {current_coach.id}")
            return jsonify({'error': 'Plan no encontrado o no autorizado'}), 404
        
        logger.info(f"📋 COACH-UPDATE: Current category: {plan.category}")
        
        # Actualizar campos permitidos
        if 'objetivo' in data:
            plan.objetivo = data['objetivo']
        
        if 'situacion_actual' in data:
            plan.situacion_actual = data['situacion_actual']
        
        if 'category' in data:
            plan.category = data['category']
            logger.info(f"✅ COACH-UPDATE: Category updated to: {plan.category}")
        
        if 'areas_desarrollo' in data:
            plan.areas_desarrollo = data['areas_desarrollo']
        
        if 'acciones' in data:
            plan.acciones = data['acciones']
        
        if 'milestones' in data:
            plan.milestones = data['milestones']
            logger.info(f"✅ COACH-UPDATE: Milestones updated: {len(data['milestones'])} hitos")
        
        if 'indicadores' in data:
            plan.indicadores = data['indicadores']
        
        if 'status' in data and data['status'] in ['draft', 'published']:
            old_status = plan.status
            plan.status = data['status']
            
            # Si se está publicando, actualizar published_at
            if data['status'] == 'published' and old_status == 'draft':
                plan.published_at = datetime.utcnow()
        
        plan.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"✅ DEV-PLAN-UPDATE: Coach {current_coach.id} updated plan {plan_id}")
        
        return jsonify({
            'success': True,
            'message': 'Plan actualizado exitosamente',
            'plan': {
                'id': plan.id,
                'status': plan.status,
                'updated_at': plan.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_update_development_plan: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al actualizar plan: {str(e)}'}), 500

@app.route('/api/coach/development-plans', methods=['GET'])
@coach_session_required
def api_coach_list_development_plans():
    """Listar planes de desarrollo del coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        status_filter = request.args.get('status')  # draft, published, in_progress, completed
        
        query = DevelopmentPlan.query.filter_by(coach_id=current_coach.id)
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        plans = query.order_by(DevelopmentPlan.created_at.desc()).all()
        
        plans_list = []
        for plan in plans:
            coachee = User.query.get(plan.coachee_id)
            plans_list.append({
                'id': plan.id,
                'coachee_id': plan.coachee_id,
                'coachee_name': coachee.full_name or coachee.username if coachee else 'N/A',
                'objetivo': plan.objetivo,
                'areas_desarrollo': plan.areas_desarrollo,
                'status': plan.status,
                'created_at': plan.created_at.isoformat(),
                'published_at': plan.published_at.isoformat() if plan.published_at else None
            })
        
        return jsonify({
            'success': True,
            'plans': plans_list
        })
        
    except Exception as e:
        logger.error(f"Error en api_coach_list_development_plans: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/development-plans/<int:plan_id>', methods=['GET'])
@coach_session_required
def api_coach_get_development_plan(plan_id):
    """Obtener un plan de desarrollo específico del coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"📋 GET-PLAN: Request for plan {plan_id} from coach {current_coach.id if current_coach else 'None'}")
        
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"❌ GET-PLAN: Access denied for plan {plan_id}")
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Buscar el plan
        plan = DevelopmentPlan.query.filter_by(
            id=plan_id,
            coach_id=current_coach.id
        ).first()
        
        if not plan:
            logger.warning(f"❌ GET-PLAN: Plan {plan_id} not found for coach {current_coach.id}")
            return jsonify({'error': 'Plan no encontrado'}), 404
        
        logger.info(f"✅ GET-PLAN: Plan {plan_id} found - Status: {plan.status}")
        
        # Obtener información del coachee
        coachee = User.query.get(plan.coachee_id)
        
        return jsonify({
            'success': True,
            'plan': {
                'id': plan.id,
                'coachee_id': plan.coachee_id,
                'coachee_name': coachee.full_name or coachee.username if coachee else 'N/A',
                'objetivo': plan.objetivo,
                'situacion_actual': plan.situacion_actual,
                'areas_desarrollo': plan.areas_desarrollo,
                'acciones': plan.acciones,
                'milestones': plan.milestones if plan.milestones else [],
                'indicadores': plan.indicadores,
                'status': plan.status,
                'created_at': plan.created_at.isoformat(),
                'published_at': plan.published_at.isoformat() if plan.published_at else None
            }
        })
        
    except Exception as e:
        logger.error(f"Error en api_coach_get_development_plan: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/development-plan/<int:plan_id>/publish', methods=['PUT'])
@coach_session_required
def api_coach_publish_development_plan(plan_id):
    """Publicar un plan de desarrollo (cambiar de draft a published)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        logger.info(f"📤 PUBLISH-PLAN: Coach {current_coach.id} intentando publicar plan {plan_id}")
        
        # Buscar el plan
        plan = DevelopmentPlan.query.filter_by(
            id=plan_id,
            coach_id=current_coach.id
        ).first()
        
        if not plan:
            logger.warning(f"❌ PUBLISH-PLAN: Plan {plan_id} no encontrado para coach {current_coach.id}")
            return jsonify({'error': 'Plan no encontrado'}), 404
        
        # Verificar que esté en estado draft
        if plan.status != 'draft':
            logger.warning(f"⚠️ PUBLISH-PLAN: Plan {plan_id} no está en draft (status: {plan.status})")
            return jsonify({'error': f'Solo se pueden publicar planes en borrador. Estado actual: {plan.status}'}), 400
        
        # Cambiar a published
        plan.status = 'published'
        plan.published_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"✅ PUBLISH-PLAN: Plan {plan_id} publicado exitosamente")
        
        return jsonify({
            'success': True,
            'message': 'Plan publicado exitosamente',
            'plan': {
                'id': plan.id,
                'status': plan.status,
                'published_at': plan.published_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_publish_development_plan: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al publicar plan: {str(e)}'}), 500

@app.route('/api/coachee/development-plans', methods=['GET'])
@coachee_session_required
def api_coachee_development_plans():
    """Obtener planes de desarrollo del coachee (solo publicados)"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        
        if not current_coachee or current_coachee.role != 'coachee':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Solo obtener planes publicados
        plans = DevelopmentPlan.query.filter_by(
            coachee_id=current_coachee.id,
            status='published'
        ).order_by(DevelopmentPlan.published_at.desc()).all()
        
        plans_list = []
        for plan in plans:
            coach = User.query.get(plan.coach_id)
            plans_list.append({
                'id': plan.id,
                'coach_name': coach.full_name or coach.username if coach else 'N/A',
                'objetivo': plan.objetivo,
                'situacion_actual': plan.situacion_actual,
                'category': getattr(plan, 'category', 'personal'),  # Default a personal si no existe
                'areas_desarrollo': plan.areas_desarrollo,
                'acciones': plan.acciones,
                'milestones': plan.milestones if plan.milestones else [],  # Hitos personalizados
                'indicadores': plan.indicadores,
                'status': plan.status,
                'created_at': plan.created_at.isoformat(),
                'published_at': plan.published_at.isoformat() if plan.published_at else None
            })
        
        logger.info(f"📋 COACHEE-PLANS: Returning {len(plans_list)} plans for coachee {current_coachee.id}")
        
        return jsonify({
            'success': True,
            'plans': plans_list
        })
        
    except Exception as e:
        logger.error(f"Error en api_coachee_development_plans: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coachee/development-plan/<int:plan_id>/progress', methods=['PUT'])
@coachee_session_required
def api_coachee_update_plan_progress(plan_id):
    """Actualizar progreso del plan (solo coachee puede actualizar acciones completadas)"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        
        logger.info(f"📝 COACHEE-PROGRESS: Coachee {current_coachee.id if current_coachee else 'None'} attempting to update plan {plan_id}")
        
        if not current_coachee or current_coachee.role != 'coachee':
            logger.warning(f"⚠️ COACHEE-PROGRESS: Access denied - user role: {current_coachee.role if current_coachee else 'None'}")
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        logger.info(f"📦 COACHEE-PROGRESS: Received data: {data}")
        
        # Buscar el plan
        plan = DevelopmentPlan.query.filter_by(
            id=plan_id,
            coachee_id=current_coachee.id,
            status='published'
        ).first()
        
        if not plan:
            logger.warning(f"⚠️ COACHEE-PROGRESS: Plan {plan_id} not found for coachee {current_coachee.id}")
            return jsonify({'error': 'Plan no encontrado o no autorizado'}), 404
        
        # Actualizar acciones completadas
        if 'acciones' in data and isinstance(data['acciones'], list):
            plan.acciones = data['acciones']
            logger.info(f"✅ COACHEE-PROGRESS: Updated {len(data['acciones'])} actions")
        
        plan.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"✅ COACHEE-PROGRESS: Coachee {current_coachee.id} updated progress for plan {plan_id}")
        
        return jsonify({
            'success': True,
            'message': 'Progreso actualizado exitosamente'
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coachee_update_plan_progress: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al actualizar progreso: {str(e)}'}), 500

@app.route('/api/coachee/development-plan/<int:plan_id>/milestones', methods=['PUT'])
@coachee_session_required
def api_coachee_update_milestones(plan_id):
    """Actualizar hitos del plan (solo coachee puede marcarlos como completados)"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        
        logger.info(f"🎯 COACHEE-MILESTONES: Coachee {current_coachee.id if current_coachee else 'None'} updating milestones for plan {plan_id}")
        
        if not current_coachee or current_coachee.role != 'coachee':
            logger.warning(f"⚠️ COACHEE-MILESTONES: Access denied")
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        logger.info(f"📦 COACHEE-MILESTONES: Received data: {data}")
        
        # Buscar el plan
        plan = DevelopmentPlan.query.filter_by(
            id=plan_id,
            coachee_id=current_coachee.id,
            status='published'
        ).first()
        
        if not plan:
            logger.warning(f"⚠️ COACHEE-MILESTONES: Plan {plan_id} not found")
            return jsonify({'error': 'Plan no encontrado o no autorizado'}), 404
        
        # Actualizar hitos
        if 'milestones' in data and isinstance(data['milestones'], list):
            plan.milestones = data['milestones']
            logger.info(f"✅ COACHEE-MILESTONES: Updated {len(data['milestones'])} milestones")
        
        plan.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"✅ COACHEE-MILESTONES: Milestones updated successfully")
        
        return jsonify({
            'success': True,
            'message': 'Hitos actualizados exitosamente'
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coachee_update_milestones: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al actualizar hitos: {str(e)}'}), 500

# ============================================
# 📝 ENDPOINTS DE CREACIÓN DE EVALUACIONES
# ============================================

@app.route('/api/coach/assessments/create', methods=['POST'])
@coach_session_required
def api_coach_create_assessment():
    """Crear una nueva evaluación (borrador o publicada)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        
        # Validar datos requeridos
        if not data.get('title'):
            return jsonify({'error': 'El título es requerido'}), 400
        
        if not data.get('questions') or not isinstance(data['questions'], list) or len(data['questions']) == 0:
            return jsonify({'error': 'Debe incluir al menos una pregunta'}), 400
        
        logger.info(f"📝 CREATE-ASSESSMENT: Coach {current_coach.username} creando evaluación '{data.get('title')}'")
        
        # Crear evaluación
        status = data.get('status', 'draft')  # Por defecto es borrador
        assessment = Assessment(
            title=data['title'],
            description=data.get('description', ''),
            category=data.get('category', 'Otros'),
            status=status,
            coach_id=current_coach.id,
            is_active=(status == 'published')  # Solo activa si está publicada
        )
        
        db.session.add(assessment)
        db.session.flush()  # Para obtener el ID
        
        # Crear preguntas
        for idx, q_data in enumerate(data['questions']):
            if not q_data.get('text'):
                continue
                
            question = Question(
                assessment_id=assessment.id,
                text=q_data['text'],
                question_type=q_data.get('type', 'likert'),
                dimension=q_data.get('dimension', ''),
                order=idx + 1,
                is_active=True
            )
            db.session.add(question)
        
        db.session.commit()
        
        logger.info(f"✅ CREATE-ASSESSMENT: Evaluación {assessment.id} creada exitosamente (status: {status})")
        
        return jsonify({
            'success': True,
            'message': f'Evaluación {"guardada como borrador" if status == "draft" else "publicada"} exitosamente',
            'assessment': {
                'id': assessment.id,
                'title': assessment.title,
                'status': assessment.status,
                'category': assessment.category,
                'questions_count': len(data['questions'])
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_create_assessment: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al crear evaluación: {str(e)}'}), 500

@app.route('/api/coach/assessments/drafts', methods=['GET'])
@coach_session_required
def api_coach_get_draft_assessments():
    """Obtener evaluaciones en borrador del coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Obtener borradores
        drafts = Assessment.query.filter_by(
            coach_id=current_coach.id,
            status='draft'
        ).order_by(Assessment.created_at.desc()).all()
        
        drafts_list = []
        for assessment in drafts:
            questions_count = Question.query.filter_by(assessment_id=assessment.id).count()
            drafts_list.append({
                'id': assessment.id,
                'title': assessment.title,
                'description': assessment.description,
                'category': assessment.category,
                'questions_count': questions_count,
                'created_at': assessment.created_at.isoformat()
            })
        
        logger.info(f"📋 DRAFT-ASSESSMENTS: Returning {len(drafts_list)} drafts for coach {current_coach.id}")
        
        return jsonify({
            'success': True,
            'drafts': drafts_list
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_get_draft_assessments: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/api/coach/assessments/<int:assessment_id>/publish', methods=['PUT'])
@coach_session_required
def api_coach_publish_assessment(assessment_id):
    """Publicar una evaluación (cambiar de draft a published)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        logger.info(f"📤 PUBLISH-ASSESSMENT: Coach {current_coach.id} publicando evaluación {assessment_id}")
        
        # Buscar la evaluación
        assessment = Assessment.query.filter_by(
            id=assessment_id,
            coach_id=current_coach.id
        ).first()
        
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        if assessment.status != 'draft':
            return jsonify({'error': 'Solo se pueden publicar evaluaciones en borrador'}), 400
        
        # Verificar que tenga preguntas
        questions_count = Question.query.filter_by(assessment_id=assessment_id).count()
        if questions_count == 0:
            return jsonify({'error': 'No se puede publicar una evaluación sin preguntas'}), 400
        
        # Cambiar a publicada
        assessment.status = 'published'
        assessment.is_active = True
        
        db.session.commit()
        
        logger.info(f"✅ PUBLISH-ASSESSMENT: Evaluación {assessment_id} publicada exitosamente")
        
        return jsonify({
            'success': True,
            'message': 'Evaluación publicada exitosamente',
            'assessment': {
                'id': assessment.id,
                'title': assessment.title,
                'status': assessment.status
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_publish_assessment: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al publicar evaluación: {str(e)}'}), 500

@app.route('/api/coach/assessments/<int:assessment_id>', methods=['DELETE'])
@coach_session_required
def api_coach_delete_assessment(assessment_id):
    """Eliminar una evaluación borrador"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Buscar la evaluación
        assessment = Assessment.query.filter_by(
            id=assessment_id,
            coach_id=current_coach.id,
            status='draft'
        ).first()
        
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada o no se puede eliminar'}), 404
        
        db.session.delete(assessment)
        db.session.commit()
        
        logger.info(f"🗑️ DELETE-ASSESSMENT: Evaluación {assessment_id} eliminada por coach {current_coach.id}")
        
        return jsonify({
            'success': True,
            'message': 'Evaluación eliminada exitosamente'
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_delete_assessment: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al eliminar evaluación: {str(e)}'}), 500

@app.route('/api/coach/assessments/<int:assessment_id>/details', methods=['GET'])
@coach_session_required
def api_coach_get_assessment_details(assessment_id):
    """Obtener detalles completos de una evaluación borrador para edición"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Buscar la evaluación
        assessment = Assessment.query.filter_by(
            id=assessment_id,
            coach_id=current_coach.id,
            status='draft'
        ).first()
        
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada o no es un borrador'}), 404
        
        # Obtener preguntas
        questions = Question.query.filter_by(
            assessment_id=assessment_id
        ).order_by(Question.order).all()
        
        questions_list = []
        for q in questions:
            questions_list.append({
                'id': q.id,
                'text': q.text,
                'dimension': q.dimension,
                'question_type': q.question_type,
                'order': q.order
            })
        
        logger.info(f"📖 GET-ASSESSMENT-DETAILS: Obteniendo detalles de evaluación {assessment_id}")
        
        return jsonify({
            'success': True,
            'assessment': {
                'id': assessment.id,
                'title': assessment.title,
                'description': assessment.description,
                'category': assessment.category,
                'status': assessment.status,
                'questions': questions_list
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_get_assessment_details: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al obtener detalles: {str(e)}'}), 500

@app.route('/api/coach/assessments/<int:assessment_id>/update', methods=['PUT'])
@coach_session_required
def api_coach_update_assessment(assessment_id):
    """Actualizar una evaluación borrador"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        
        # Validar datos requeridos
        if not data.get('title'):
            return jsonify({'error': 'El título es requerido'}), 400
        
        if not data.get('questions') or not isinstance(data['questions'], list) or len(data['questions']) == 0:
            return jsonify({'error': 'Debe incluir al menos una pregunta'}), 400
        
        # Buscar la evaluación
        assessment = Assessment.query.filter_by(
            id=assessment_id,
            coach_id=current_coach.id,
            status='draft'
        ).first()
        
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada o no se puede editar'}), 404
        
        logger.info(f"📝 UPDATE-ASSESSMENT: Coach {current_coach.username} actualizando evaluación {assessment_id}")
        
        # Actualizar campos
        assessment.title = data['title']
        assessment.description = data.get('description')
        assessment.category = data.get('category')
        
        # Eliminar preguntas anteriores
        Question.query.filter_by(assessment_id=assessment_id).delete()
        
        # Agregar nuevas preguntas
        for q_data in data['questions']:
            question = Question(
                assessment_id=assessment.id,
                text=q_data['text'],
                dimension=q_data.get('dimension'),
                question_type=q_data.get('question_type', 'likert'),
                order=q_data.get('order', 1)
            )
            db.session.add(question)
        
        db.session.commit()
        
        logger.info(f"✅ UPDATE-ASSESSMENT: Evaluación {assessment_id} actualizada exitosamente")
        
        return jsonify({
            'success': True,
            'message': 'Evaluación actualizada exitosamente',
            'assessment': {
                'id': assessment.id,
                'title': assessment.title,
                'status': assessment.status,
                'category': assessment.category,
                'questions_count': len(data['questions'])
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_update_assessment: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al actualizar evaluación: {str(e)}'}), 500

@app.route('/api/coach/assessments/<int:assessment_id>/delete-published', methods=['DELETE'])
@coach_session_required
def api_coach_delete_published_assessment(assessment_id):
    """Eliminar una evaluación publicada (solo si no tiene resultados)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Buscar la evaluación
        assessment = Assessment.query.get(assessment_id)
        
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        # Verificar que es del coach o que puede ser eliminada
        # Permitir eliminar si: es del coach Y no tiene resultados
        # O si no tiene coach_id (evaluaciones del sistema con permiso especial)
        if assessment.coach_id and assessment.coach_id != current_coach.id:
            return jsonify({'error': 'No tienes permiso para eliminar esta evaluación'}), 403
        
        # Verificar si tiene resultados
        results_count = AssessmentResult.query.filter_by(assessment_id=assessment_id).count()
        if results_count > 0:
            return jsonify({
                'error': f'No se puede eliminar. Esta evaluación tiene {results_count} resultado(s) asociado(s).'
            }), 400
        
        # Verificar si está asignada a coachees
        tasks_count = Task.query.filter(
            Task.title.like(f'%{assessment.title}%'),
            Task.category == 'evaluation',
            Task.is_active == True
        ).count()
        
        if tasks_count > 0:
            return jsonify({
                'error': f'No se puede eliminar. Esta evaluación está asignada a {tasks_count} coachee(s).'
            }), 400
        
        logger.info(f"🗑️ DELETE-PUBLISHED-ASSESSMENT: Eliminando evaluación {assessment_id} por coach {current_coach.id}")
        
        # Eliminar preguntas asociadas
        Question.query.filter_by(assessment_id=assessment_id).delete()
        
        # Eliminar la evaluación
        db.session.delete(assessment)
        db.session.commit()
        
        logger.info(f"✅ DELETE-PUBLISHED-ASSESSMENT: Evaluación {assessment_id} eliminada exitosamente")
        
        return jsonify({
            'success': True,
            'message': 'Evaluación eliminada exitosamente'
        })
        
    except Exception as e:
        logger.error(f"❌ Error en api_coach_delete_published_assessment: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al eliminar evaluación: {str(e)}'}), 500

@app.route('/api/coach/pending-evaluations', methods=['GET'])
@coach_session_required
def api_coach_pending_evaluations():
    """Obtener evaluaciones pendientes de todos los coachees del coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        logger.info(f"🔍 PENDING-EVALUATIONS: Request from coach {current_coach.username} (ID: {current_coach.id})")
        
        # Obtener todos los coachees del coach
        coachees = User.query.filter_by(coach_id=current_coach.id, role='coachee').all()
        coachee_ids = [c.id for c in coachees]
        
        # OPTIMIZACIÓN: Obtener todas las tareas de evaluación de una vez
        eval_tasks = Task.query.filter(
            Task.coachee_id.in_(coachee_ids),
            Task.category == 'evaluation',
            Task.is_active == True
        ).all() if coachee_ids else []
        
        logger.info(f"📊 PENDING-EVALUATIONS: Found {len(eval_tasks)} evaluation tasks for {len(coachees)} coachees")
        
        # OPTIMIZACIÓN: Precalcular task progress en una query
        task_ids = [t.id for t in eval_tasks]
        progress_dict = {}
        if task_ids:
            try:
                progresses = TaskProgress.query.filter(TaskProgress.task_id.in_(task_ids)).all()
                progress_dict = {tp.task_id: tp for tp in progresses}
                logger.info(f"📊 PENDING-EVALUATIONS: Loaded progress for {len(progress_dict)} tasks")
            except Exception as tp_error:
                logger.warning(f"⚠️ PENDING-EVALUATIONS: Could not load task progress: {str(tp_error)}")
        
        # OPTIMIZACIÓN: Cargar todos los assessments de una vez
        all_assessments = {a.title: a for a in Assessment.query.all()}
        
        # OPTIMIZACIÓN: Precalcular resultados completados después de asignación en una query
        # Crear un diccionario de (user_id, assessment_id) -> [results]
        completed_results = {}
        if eval_tasks:
            try:
                # Obtener todos los resultados relevantes
                assessment_ids_set = set()
                for task in eval_tasks:
                    # Extraer título de la evaluación del task title (usando misma lógica que abajo)
                    title_match = task.title
                    # Remover prefijos comunes
                    for prefix in ['Completar: ', 'Evaluación: ', 'Realizar: ', 'Hacer: ']:
                        if title_match.startswith(prefix):
                            title_match = title_match[len(prefix):]
                            break
                    # Remover sufijos
                    title_match = title_match.split(' (')[0].strip()
                    
                    # Buscar assessment
                    if title_match in all_assessments:
                        assessment_ids_set.add(all_assessments[title_match].id)
                    else:
                        for title, assessment in all_assessments.items():
                            if title_match in title or title in title_match:
                                assessment_ids_set.add(assessment.id)
                                break
                
                if assessment_ids_set and coachee_ids:
                    results = AssessmentResult.query.filter(
                        AssessmentResult.user_id.in_(coachee_ids),
                        AssessmentResult.assessment_id.in_(list(assessment_ids_set))
                    ).all()
                    
                    for result in results:
                        key = (result.user_id, result.assessment_id)
                        if key not in completed_results:
                            completed_results[key] = []
                        completed_results[key].append(result)
                    
                    logger.info(f"📊 PENDING-EVALUATIONS: Loaded {len(results)} completed results")
            except Exception as cr_error:
                logger.warning(f"⚠️ PENDING-EVALUATIONS: Could not load completed results: {str(cr_error)}")
        
        # Crear diccionario de coachees por ID
        coachees_dict = {c.id: c for c in coachees}
        
        pending_evaluations = []
        
        # Procesar todas las tareas usando datos precargados
        for task in eval_tasks:
            coachee = coachees_dict.get(task.coachee_id)
            if not coachee:
                continue
            
            # Extraer título de la evaluación del task title (soporta múltiples formatos)
            title_match = task.title
            # Remover prefijos comunes: "Completar: ", "Evaluación: ", etc.
            for prefix in ['Completar: ', 'Evaluación: ', 'Realizar: ', 'Hacer: ']:
                if title_match.startswith(prefix):
                    title_match = title_match[len(prefix):]
                    break
            # Remover sufijos como " (Pendiente)"
            title_match = title_match.split(' (')[0].strip()
            
            # Buscar assessment en diccionario precargado por coincidencia exacta o parcial
            assessment = None
            # Primero intentar coincidencia exacta
            if title_match in all_assessments:
                assessment = all_assessments[title_match]
            else:
                # Si no hay coincidencia exacta, buscar coincidencia parcial
                for title, a in all_assessments.items():
                    if title_match in title or title in title_match:
                        assessment = a
                        break
            
            if assessment:
                # Verificar si fue completada DESPUÉS de ser asignada usando datos precargados
                key = (coachee.id, assessment.id)
                completed_after_assignment = None
                
                if key in completed_results:
                    for result in completed_results[key]:
                        if result.completed_at >= task.created_at:
                            completed_after_assignment = result
                            break
                
                if not completed_after_assignment:
                    # Esta evaluación está PENDIENTE
                    progress = progress_dict.get(task.id)
                    
                    pending_evaluations.append({
                        'task_id': task.id,
                        'assessment_id': assessment.id,
                        'assessment_title': assessment.title,
                        'coachee_id': coachee.id,
                        'coachee_name': coachee.full_name or coachee.username,
                        'coachee_email': coachee.email,
                        'assigned_date': task.created_at.isoformat(),
                        'status': progress.status if progress else 'pending'
                    })
        
        logger.info(f"📊 PENDING-EVALUATIONS: Found {len(pending_evaluations)} pending evaluations")
        
        return jsonify({
            'success': True,
            'pending_evaluations': pending_evaluations,
            'total': len(pending_evaluations)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ PENDING-EVALUATIONS: Error getting pending evaluations: {str(e)}")
        logger.error(f"❌ PENDING-EVALUATIONS: Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Error obteniendo evaluaciones pendientes: {str(e)}'}), 500

@app.route('/api/coach/tasks', methods=['GET'])
@coach_session_required
def api_coach_tasks_get():
    """Obtener tareas del coach"""
    try:
        app.logger.info(f"=== OBTENER TAREAS - Usuario: {g.current_user.email} ===")
        
        # Verificar que es un coach
        if not g.current_user or g.current_user.role != 'coach':
            app.logger.error(f"Acceso denegado - Usuario: {g.current_user.email}, Role: {g.current_user.role}")
            return jsonify({'error': 'Acceso denegado.'}), 403
        
        # Obtener todas las tareas asignadas por el coach, excluyendo evaluaciones
        tasks = Task.query.filter(
            Task.coach_id == g.current_user.id,
            Task.is_active == True,
            Task.category != 'evaluation'
        ).all()
        app.logger.info(f"Tareas encontradas: {len(tasks)}")
        
        # OPTIMIZACIÓN: Precalcular últimos progresos en una query usando subquery
        task_ids = [t.id for t in tasks]
        latest_progress_dict = {}
        
        if task_ids:
            try:
                # Subquery para obtener la fecha más reciente por tarea
                subq = db.session.query(
                    TaskProgress.task_id,
                    func.max(TaskProgress.created_at).label('max_date')
                ).filter(
                    TaskProgress.task_id.in_(task_ids)
                ).group_by(TaskProgress.task_id).subquery()
                
                # Query principal para obtener los datos completos del último progreso
                latest_progresses = db.session.query(TaskProgress).join(
                    subq,
                    and_(
                        TaskProgress.task_id == subq.c.task_id,
                        TaskProgress.created_at == subq.c.max_date
                    )
                ).all()
                
                latest_progress_dict = {tp.task_id: tp for tp in latest_progresses}
                app.logger.info(f"📊 TASKS: Loaded latest progress for {len(latest_progress_dict)} tasks")
            except Exception as tp_error:
                app.logger.warning(f"⚠️ TASKS: Could not load task progress: {str(tp_error)}")
        
        tasks_data = []
        for task in tasks:
            # Usar progreso precargado
            latest_progress = latest_progress_dict.get(task.id)
            
            task_data = {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'category': task.category,
                'priority': task.priority,
                'type': getattr(task, 'type', 'accion'),
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
        app.logger.info(f"=== INICIO CREACIÓN TAREA - Usuario: {g.current_user.email} ===")
        
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
            coach_id=g.current_user.id,
            role='coachee'
        ).first()
        
        if not coachee:
            app.logger.error(f"Coachee no encontrado - ID: {data['coachee_id']}, Coach ID: {g.current_user.id}")
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
            coach_id=g.current_user.id,
            coachee_id=data['coachee_id'],
            title=data['title'],
            description=data['description'],
            category=data['category'],
            priority=data.get('priority', 'medium'),
            type=data.get('type', 'accion'),
            due_date=due_date
        )
        
        app.logger.info(f"Tarea creada, agregando a sesión...")
        db.session.add(new_task)
        db.session.flush()
        app.logger.info(f"Tarea agregada con ID: {new_task.id}")
        
        # GAMIFICACIÓN: Guardar configuración de puntos (Etapa 4.3)
        difficulty = data.get('difficulty')
        points = data.get('points')
        
        if difficulty and points:
            app.logger.info(f"🎮 GAMIFICACIÓN: Guardando configuración - Dificultad: {difficulty}, Puntos: {points}")
            
            points_config = db.session.execute(
                text("""
                    INSERT INTO task_points_config 
                    (task_id, difficulty_level, base_points, bonus_multiplier, category_bonus, 
                     is_repeatable, max_repetitions, created_by_coach_id, created_at)
                    VALUES (:task_id, :difficulty, :points, 1.0, 0, FALSE, 1, :coach_id, :created_at)
                """),
                {
                    'task_id': new_task.id,
                    'difficulty': difficulty,
                    'points': points,
                    'coach_id': g.current_user.id,
                    'created_at': datetime.utcnow()
                }
            )
            app.logger.info(f"✅ GAMIFICACIÓN: Configuración guardada para tarea {new_task.id}")
        else:
            app.logger.info(f"⚠️ GAMIFICACIÓN: No se proporcionó dificultad/puntos, tarea sin configuración de puntos")
        
        # Crear entrada inicial de progreso
        app.logger.info(f"Creando progreso inicial...")
        initial_progress = TaskProgress(
            task_id=new_task.id,
            status='pending',
            progress_percentage=0,
            notes='Tarea creada',
            updated_by=g.current_user.id
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
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': f'Error creando tarea: {str(e)}'}), 500

@app.route('/api/coach/tasks/<int:task_id>', methods=['PUT'])
@coach_session_required
def api_coach_update_task(task_id):
    """Actualizar una tarea existente"""
    try:
        app.logger.info(f"=== INICIO ACTUALIZACIÓN TAREA {task_id} - Usuario: {g.current_user.email} ===")
        
        # Buscar la tarea
        task = Task.query.filter_by(id=task_id, coach_id=g.current_user.id).first()
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
            coachee = User.query.filter_by(id=data['coachee_id'], coach_id=g.current_user.id, role='coachee').first()
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

@app.route('/api/coach/assign-evaluation', methods=['POST'])
@coach_session_required
def api_coach_assign_evaluation():
    """Asignar una evaluación a un coachee creando una tarea"""
    try:
        current_coach = g.current_user
        app.logger.info(f"=== ASIGNAR EVALUACIÓN - Coach: {current_coach.email} ===")
        
        data = request.get_json()
        app.logger.info(f"Datos recibidos: {data}")
        
        # Validar datos requeridos
        assessment_id = data.get('assessment_id')
        coachee_id = data.get('coachee_id')
        
        if not assessment_id or not coachee_id:
            app.logger.error("Faltan campos requeridos: assessment_id o coachee_id")
            return jsonify({'error': 'assessment_id y coachee_id son requeridos'}), 400
        
        # Verificar que el assessment existe
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            app.logger.error(f"Assessment no encontrado: {assessment_id}")
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        # Verificar que el coachee existe y pertenece al coach
        coachee = User.query.filter_by(
            id=coachee_id,
            coach_id=current_coach.id,
            role='coachee'
        ).first()
        
        if not coachee:
            app.logger.error(f"Coachee no encontrado o no asignado: {coachee_id}")
            return jsonify({'error': 'Coachee no encontrado o no asignado a este coach'}), 404
        
        app.logger.info(f"Asignando evaluación '{assessment.title}' a coachee {coachee.email}")
        
        # Crear una tarea para la evaluación
        message = data.get('message', f'Por favor completa la evaluación: {assessment.title}')
        due_date = None
        if data.get('due_date'):
            try:
                due_date = datetime.fromisoformat(data['due_date']).date()
            except ValueError:
                app.logger.warning(f"Formato de fecha inválido: {data['due_date']}")
        
        # Crear la tarea con category='evaluation' para identificarla como asignación de evaluación
        new_task = Task(
            coach_id=current_coach.id,
            coachee_id=coachee_id,
            title=f"Completar: {assessment.title}",
            description=message,
            category='evaluation',
            priority='high',
            due_date=due_date
        )
        
        db.session.add(new_task)
        db.session.flush()
        
        # Crear entrada inicial de progreso
        initial_progress = TaskProgress(
            task_id=new_task.id,
            status='pending',
            progress_percentage=0,
            notes='Evaluación asignada',
            updated_by=current_coach.id
        )
        
        db.session.add(initial_progress)
        db.session.commit()
        
        app.logger.info(f"✅ Evaluación asignada exitosamente - Tarea ID: {new_task.id}")
        
        return jsonify({
            'success': True,
            'message': 'Evaluación asignada exitosamente',
            'task_id': new_task.id
        }), 201
        
    except Exception as e:
        app.logger.error(f"❌ ERROR ASIGNANDO EVALUACIÓN: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': f'Error asignando evaluación: {str(e)}'}), 500

@app.route('/api/coach/coachee-assessments/<int:coachee_id>', methods=['GET'])
@coach_session_required
def api_coach_coachee_assessments(coachee_id):
    """Obtener todas las evaluaciones disponibles para un coachee específico (espejo del dashboard del coachee)"""
    try:
        logger.info(f"📊 COACHEE-ASSESSMENTS: Request from user {current_user.username} for coachee {coachee_id}")
        
        if not current_user.is_authenticated or current_user.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver evaluaciones de coachees.'}), 403
        
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=g.current_user.id, role='coachee').first()
        if not coachee:
            logger.warning(f"❌ COACHEE-ASSESSMENTS: Coachee {coachee_id} not found or unauthorized")
            return jsonify({'error': 'Coachee no encontrado o no autorizado.'}), 404
        
        logger.info(f"🔍 COACHEE-ASSESSMENTS: Getting ALL available assessments for {coachee.full_name} (mirror view)")
        
        # 1. Obtener todas las evaluaciones disponibles (igual que ve el coachee)
        available_assessments = Assessment.query.filter(Assessment.is_active == True).all()
        
        # 2. Obtener tareas de evaluación asignadas a este coachee
        evaluation_tasks = Task.query.filter_by(
            coach_id=g.current_user.id,
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
        coachee = User.query.filter_by(id=coachee_id, coach_id=g.current_user.id, role='coachee').first()
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
                coach_id=g.current_user.id,
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
            # PostgreSQL: usar solo True (no 1, causa error de tipo)
            assessments = Assessment.query.filter(
                Assessment.is_active == True
            ).all()
            app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: Found {len(assessments)} active assessments")
            
            # Log detallado de las evaluaciones encontradas
            for assessment in assessments:
                app.logger.info(f"  • Assessment ID {assessment.id}: {assessment.title} (is_active={assessment.is_active}, status={assessment.status})")
        except Exception as db_error:
            app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Database query failed: {str(db_error)}")
            # Intentar crear evaluaciones si no existen
            try:
                create_additional_assessments()
                assessments = Assessment.query.filter(
                    Assessment.is_active == True
                ).all()
                app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: After creation attempt, found {len(assessments)} assessments")
            except Exception as create_error:
                app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Could not create assessments: {str(create_error)}")
                assessments = []
        
        # OPTIMIZACIÓN: Obtener todos los conteos en 2 queries agrupadas en lugar de N queries
        assessment_ids = [a.id for a in assessments]
        
        # Query agrupada para contar preguntas por evaluación
        questions_counts = {}
        try:
            question_counts_result = db.session.query(
                Question.assessment_id,
                func.count(Question.id)
            ).filter(
                Question.assessment_id.in_(assessment_ids),
                Question.is_active == True
            ).group_by(Question.assessment_id).all()
            questions_counts = {aid: count for aid, count in question_counts_result}
            app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: Loaded question counts for {len(questions_counts)} assessments")
        except Exception as q_error:
            app.logger.warning(f"⚠️ AVAILABLE-ASSESSMENTS: Could not load question counts: {str(q_error)}")
        
        # Query agrupada para contar resultados completados por evaluación
        completed_counts = {}
        try:
            results_counts_result = db.session.query(
                AssessmentResult.assessment_id,
                func.count(AssessmentResult.id)
            ).filter(
                AssessmentResult.assessment_id.in_(assessment_ids)
            ).group_by(AssessmentResult.assessment_id).all()
            completed_counts = {aid: count for aid, count in results_counts_result}
            app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: Loaded completed counts for {len(completed_counts)} assessments")
        except Exception as r_error:
            app.logger.warning(f"⚠️ AVAILABLE-ASSESSMENTS: Could not load completed counts: {str(r_error)}")
        
        # Construir datos de respuesta usando los conteos precargados
        assessments_data = []
        for assessment in assessments:
            try:
                assessment_data = {
                    'id': assessment.id,
                    'title': assessment.title or 'Sin título',
                    'description': assessment.description or 'Sin descripción',
                    'category': assessment.category or 'Otros',
                    'questions_count': questions_counts.get(assessment.id, 0),
                    'completed_count': completed_counts.get(assessment.id, 0),
                    'created_at': assessment.created_at.isoformat() if assessment.created_at else None
                }
                
                assessments_data.append(assessment_data)
                app.logger.info(f"✅ AVAILABLE-ASSESSMENTS: Processed assessment {assessment.id}: {assessment.title} (category: '{assessment.category}')")
                
            except Exception as process_error:
                app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Error processing assessment {assessment.id}: {str(process_error)}")
                # Continuar con las demás evaluaciones
                continue
        
        # Log de categorías encontradas
        categories_found = set(a['category'] for a in assessments_data)
        app.logger.info(f"📊 AVAILABLE-ASSESSMENTS: Categories found: {sorted(categories_found)}")
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
        app.logger.error(f"❌ AVAILABLE-ASSESSMENTS: Traceback: {traceback.format_exc()}")
        
        # Intentar regresar una respuesta mínima de emergencia
        return jsonify({
            'success': False,
            'error': f'Error obteniendo evaluaciones: {str(e)}',
            'assessments': [],
            'total': 0,
            'message': 'Error interno del servidor'
        }), 500

@app.route('/api/assessments/<int:assessment_id>/questions', methods=['GET'])
@coach_session_required
def api_get_assessment_questions(assessment_id):
    """Obtener las preguntas de una evaluación específica"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        app.logger.info(f"=== OBTENIENDO PREGUNTAS - Evaluación: {assessment_id}, Usuario: {current_coach.email if current_coach else 'Unknown'} ===")
        
        if not current_coach or current_coach.role != 'coach':
            app.logger.warning(f"❌ GET-QUESTIONS: Access denied for user {current_coach.username if current_coach else 'None'}")
            return jsonify({'error': 'Acceso denegado.'}), 403
        
        # Verificar que la evaluación existe
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            app.logger.warning(f"❌ GET-QUESTIONS: Assessment {assessment_id} not found")
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        app.logger.info(f"🔍 GET-QUESTIONS: Querying questions for assessment {assessment_id}: {assessment.title}")
        
        # Obtener las preguntas de la evaluación
        questions = Question.query.filter_by(
            assessment_id=assessment_id,
            is_active=True
        ).order_by(Question.id).all()
        
        app.logger.info(f"📊 GET-QUESTIONS: Found {len(questions)} questions")
        
        questions_data = []
        for question in questions:
            try:
                # Determinar opciones según el tipo de pregunta
                options = None
                if question.question_type == 'likert' or question.question_type is None:
                    # Para preguntas tipo Likert, mostrar escala estándar (1-5)
                    options = [
                        "1 - Totalmente en desacuerdo",
                        "2 - En desacuerdo",
                        "3 - Neutral",
                        "4 - De acuerdo",
                        "5 - Totalmente de acuerdo"
                    ]
                elif question.question_type == 'likert_3_scale':
                    # Para preguntas tipo Likert escala 1-3 (Preparación para crecer 2026)
                    # Opciones específicas por dimensión
                    growth_options_by_dimension = {
                        'Delegación': ['1 - Todo depende de mí', '2 - Delego algo, pero sigo resolviendo mucho', '3 - Mi equipo opera sin mí'],
                        'Estructura organizacional': ['1 - Todo es improvisado', '2 - Algunas áreas tienen estructura', '3 - Todo está formalizado'],
                        'Gestión del tiempo del dueño': ['1 - > 8 h', '2 - 4–7 h', '3 - < 4 h (más foco en estrategia)'],
                        'Finanzas': ['1 - No confío / errores frecuentes', '2 - Parcialmente actualizada', '3 - Confiable y oportuna'],
                        'Crecimiento estratégico': ['1 - Miedo de perder control', '2 - Quiero crecer pero no sé cómo', '3 - Preparado con estrategia'],
                        'Bienestar personal': ['1 - Agotado', '2 - Cansado pero motivado', '3 - Con energía y foco'],
                        'Visión a futuro': ['1 - Frustrado', '2 - Inquieto pero optimista', '3 - Orgulloso']
                    }
                    # Obtener opciones específicas según la dimensión de la pregunta
                    dimension = question.dimension.strip() if question.dimension else None
                    options = growth_options_by_dimension.get(dimension, ['1 - Opción 1', '2 - Opción 2', '3 - Opción 3'])
                
                question_data = {
                    'id': question.id,
                    'question_text': question.text,  # El campo correcto es 'text'
                    'question_type': question.question_type or 'likert',
                    'options': options,
                    'dimension': question.dimension
                }
                
                questions_data.append(question_data)
                
            except Exception as q_error:
                app.logger.error(f"❌ GET-QUESTIONS: Error processing question {question.id}: {str(q_error)}")
                continue
        
        app.logger.info(f"📤 GET-QUESTIONS: Returning {len(questions_data)} questions")
        
        return jsonify({
            'success': True,
            'questions': questions_data,
            'total': len(questions_data),
            'assessment_title': assessment.title,
            'message': f'Se encontraron {len(questions_data)} preguntas'
        }), 200
        
    except Exception as e:
        app.logger.error(f"❌ GET-QUESTIONS: Critical error: {str(e)}")
        app.logger.error(f"❌ GET-QUESTIONS: Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Error obteniendo preguntas: {str(e)}',
            'questions': [],
            'total': 0
        }), 500

@app.route('/api/admin/create-additional-assessments', methods=['POST'])
@admin_required
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
@admin_required
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
@admin_required
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

@app.route('/api/coach/coachee-evaluations/<int:coachee_id>', methods=['GET'])
@coach_session_required
def api_coach_coachee_evaluations(coachee_id):
    """Obtener evaluaciones de un coachee específico"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"🔍 COACHEE-EVALUATIONS: Request for coachee_id={coachee_id} from user {current_coach.username if current_coach else 'Unknown'} (ID: {current_coach.id if current_coach else 'Unknown'}, Role: {current_coach.role if current_coach else 'Unknown'})")
        
        # Verificar que es un coach autenticado
        if not current_coach:
            logger.warning(f"❌ COACHEE-EVALUATIONS: User not authenticated")
            return jsonify({'error': 'Usuario no autenticado.'}), 401
            
        if current_coach.role != 'coach':
            logger.warning(f"❌ COACHEE-EVALUATIONS: Access denied - user {current_coach.username} (role: {current_coach.role}) is not a coach")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden acceder.'}), 403
        
        # Verificar que el coachee existe y pertenece al coach
        coachee = User.query.filter_by(id=coachee_id, role='coachee').first()
        if not coachee:
            logger.warning(f"❌ COACHEE-EVALUATIONS: Coachee {coachee_id} not found")
            return jsonify({'error': 'Coachee no encontrado.'}), 404
            
        # Verificar que el coachee está asignado al coach
        if coachee.coach_id != current_coach.id:
            logger.warning(f"❌ COACHEE-EVALUATIONS: Coachee {coachee_id} (coach_id: {coachee.coach_id}) not assigned to coach {current_coach.id}")
            return jsonify({'error': 'Este coachee no está asignado a tu cuenta.'}), 403
        
        logger.info(f"✅ COACHEE-EVALUATIONS: Coachee {coachee.full_name} found and authorized for coach {current_coach.full_name}")
        
        # Obtener evaluaciones del coachee que pertenecen al coach
        # Incluir tanto evaluaciones con coach_id correcto como NULL (para compatibilidad)
        evaluations = db.session.query(AssessmentResult, Assessment).join(
            Assessment, AssessmentResult.assessment_id == Assessment.id
        ).filter(
            AssessmentResult.user_id == coachee_id,
            db.or_(
                AssessmentResult.coach_id == current_coach.id,
                AssessmentResult.coach_id.is_(None)
            )
        ).order_by(AssessmentResult.completed_at.desc()).all()
        
        logger.info(f"📊 COACHEE-EVALUATIONS: Found {len(evaluations)} evaluations for coachee {coachee_id}")
        
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
                'dimensional_scores': result.dimensional_scores,
                'coach_id_in_evaluation': result.coach_id
            }
            evaluations_data.append(eval_data)
            logger.info(f"📋 COACHEE-EVALUATIONS: Evaluation {result.id} - {assessment.title} - Score: {result.score} - Coach ID: {result.coach_id}")
        
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
        logger.error(f"❌ COACHEE-EVALUATIONS: Error - {str(e)}")
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
        
        # 🔥 IMPORTANTE: Obtener solo evaluaciones REALMENTE completadas (con completed_at)
        completed_results = AssessmentResult.query.filter(
            AssessmentResult.user_id == current_user.id,
            AssessmentResult.completed_at.isnot(None)  # 🔥 Solo las que tienen fecha de completado
        ).all()
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
        for task in assigned_tasks:
            logger.info(f"🔍 DEBUG: Tarea encontrada - ID: {task.id}, Título: '{task.title}'")
        
        # 🔥 NUEVO: Mapear evaluaciones a sus tareas de asignación (para rastrear fecha de asignación)
        # Esto permite saber si una evaluación fue completada DESPUÉS de ser asignada
        assigned_assessment_ids = []
        assessment_task_map = {}  # {assessment_id: task}
        
        for task in assigned_tasks:
            # Remover el prefijo "Completar: " si existe
            assessment_title_from_task = task.title.replace('Completar: ', '').strip()
            logger.info(f"🔍 DEBUG: Buscando evaluación con título: '{assessment_title_from_task}'")
            
            # Buscar la evaluación que coincida exactamente con el título
            matching_assessment = Assessment.query.filter(
                Assessment.title == assessment_title_from_task,
                Assessment.is_active == True
            ).first()
            
            if matching_assessment:
                assigned_assessment_ids.append(matching_assessment.id)
                assessment_task_map[matching_assessment.id] = task  # 🔥 Guardar la tarea
                logger.info(f"🎯 DEBUG: Found assigned assessment: {matching_assessment.title} (ID: {matching_assessment.id}, Task created: {task.created_at})")
            else:
                # Fallback: buscar si el título está contenido (para compatibilidad con títulos antiguos)
                for assessment in Assessment.query.filter(Assessment.is_active == True).all():
                    if assessment.title in task.title or assessment.title == assessment_title_from_task:
                        if assessment.id not in assigned_assessment_ids:
                            assigned_assessment_ids.append(assessment.id)
                            assessment_task_map[assessment.id] = task  # 🔥 Guardar la tarea
                            logger.info(f"🎯 DEBUG: Found assigned assessment (fallback): {assessment.title} (ID: {assessment.id}, Task created: {task.created_at})")
                        break
                else:
                    logger.warning(f"⚠️ DEBUG: No se encontró evaluación para la tarea: '{task.title}'")
        
        logger.info(f"🔍 DEBUG: IDs de evaluaciones asignadas: {assigned_assessment_ids}")
        
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
            
            # 🔥 LÓGICA CORRECTA: Una evaluación está completada para esta asignación si:
            # Existe un resultado completado DESPUÉS de la fecha de asignación (Task.created_at)
            task = assessment_task_map.get(assessment.id)
            task_created_at = task.created_at if task else None
            
            # Contar TODOS los intentos previos
            all_results = [r for r in completed_results if r.assessment_id == assessment.id]
            previous_attempts = len(all_results)
            
            # Verificar si fue completada DESPUÉS de la asignación actual
            if task_created_at:
                results_after_assignment = [r for r in all_results if r.completed_at > task_created_at]
                has_completed = len(results_after_assignment) > 0
                logger.info(f"🔍 DEBUG: Assessment {assessment.id} - Task created: {task_created_at}, Resultados después de asignación: {len(results_after_assignment)}")
            else:
                # Si no hay task (no debería pasar), usar lógica antigua
                has_completed = previous_attempts > 0
                logger.warning(f"⚠️ DEBUG: Assessment {assessment.id} no tiene task asociada, usando lógica de fallback")
            
            logger.info(f"🔍 DEBUG: Assessment {assessment.id} ({assessment.title}) - {previous_attempts} intentos totales, completada esta asignación: {has_completed}")
            
            # 🔥 IMPORTANTE: TODAS las evaluaciones asignadas van a 'available' (no filtrar por completadas)
            available_evaluations[str(assessment.id)] = {
                'id': assessment.id,
                'title': assessment.title,
                'description': assessment.description,
                'total_questions': len(questions),
                'previous_attempts': previous_attempts,
                'is_completed': has_completed,  # 🔥 NUEVO FLAG
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

@app.route('/api/coachee/pending-evaluations', methods=['GET'])
@coachee_session_required
def api_coachee_pending_evaluations():
    """Obtener evaluaciones pendientes del coachee actual"""
    try:
        current_user = g.current_user
        logger.info(f"🔍 COACHEE-PENDING: User {current_user.username} (ID: {current_user.id}) requesting pending evaluations")
        
        # Verificar que tenga coach asignado
        if not current_user.coach_id:
            return jsonify({
                'success': True,
                'pending_evaluations': [],
                'total': 0
            }), 200
        
        # Obtener tareas de evaluación asignadas
        assigned_tasks = Task.query.filter_by(
            coachee_id=current_user.id,
            is_active=True,
            category='evaluation'
        ).all()
        
        # Obtener todas las evaluaciones completadas con sus fechas
        completed_results = AssessmentResult.query.filter_by(user_id=current_user.id).all()
        
        pending_evaluations = []
        
        # Para cada tarea, verificar si está pendiente
        for task in assigned_tasks:
            # Buscar la evaluación que coincida con el título de la tarea
            for assessment in Assessment.query.filter(Assessment.is_active == True).all():
                if assessment.title in task.title:
                    # Verificar si hay alguna completación DESPUÉS de la asignación
                    is_pending = True
                    
                    for result in completed_results:
                        if result.assessment_id == assessment.id:
                            # Comparar fechas: ¿La evaluación fue completada DESPUÉS de asignada?
                            if result.completed_at and task.created_at:
                                if result.completed_at > task.created_at:
                                    # Se completó después de ser asignada = NO está pendiente
                                    is_pending = False
                                    logger.info(f"✅ COACHEE-PENDING: {assessment.title} completed after assignment (Task: {task.created_at}, Completed: {result.completed_at})")
                                    break
                    
                    if is_pending:
                        # Esta evaluación está PENDIENTE (nunca completada o completada antes de la asignación actual)
                        questions = Question.query.filter_by(
                            assessment_id=assessment.id,
                            is_active=True
                        ).count()
                        
                        logger.info(f"⏳ COACHEE-PENDING: {assessment.title} is PENDING (assigned: {task.created_at})")
                        
                        pending_evaluations.append({
                            'task_id': task.id,
                            'assessment_id': assessment.id,
                            'assessment_title': assessment.title,
                            'assessment_description': assessment.description,
                            'total_questions': questions,
                            'assigned_date': task.created_at.isoformat(),
                            'priority': task.priority,
                            'coach_name': current_user.coach.full_name if current_user.coach else 'Sin asignar'
                        })
                    break
        
        logger.info(f"📊 COACHEE-PENDING: Found {len(pending_evaluations)} pending evaluations")
        
        return jsonify({
            'success': True,
            'pending_evaluations': pending_evaluations,
            'total': len(pending_evaluations)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ COACHEE-PENDING: Error getting pending evaluations: {str(e)}")
        logger.error(f"❌ COACHEE-PENDING: Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Error obteniendo evaluaciones pendientes: {str(e)}'}), 500

@app.route('/api/coachee/evaluation-history', methods=['GET'])
@coachee_session_required
def api_coachee_evaluation_history():
    """Obtener historial detallado de evaluaciones del coachee incluyendo intentos múltiples"""
    try:
        logger.info(f"🔍 EVALUATION-HISTORY: User {g.current_user.username} (ID: {g.current_user.id}) requesting evaluation history")
        # Obtener todas las evaluaciones completadas
        results = AssessmentResult.query.filter_by(user_id=g.current_user.id).order_by(
            AssessmentResult.completed_at.asc()
        ).all()
        
        history = []
        expanded_history = []  # Historial expandido con todos los intentos
        
        for result in results:
            # Intentar obtener assessment, manejar columnas faltantes
            try:
                assessment = Assessment.query.get(result.assessment_id)
            except Exception as e:
                logger.warning(f"⚠️ Error loading assessment {result.assessment_id}: {e}")
                # Crear objeto dummy si falla
                class DummyAssessment:
                    title = 'Evaluación'
                    description = None
                assessment = DummyAssessment()
            
            invitation = result.invitation
            
            # Información básica del resultado actual
            basic_info = {
                'id': result.id,
                'assessment': {
                    'id': result.assessment_id,
                    'title': assessment.title if assessment else 'Evaluación eliminada',
                    'description': assessment.description if assessment else None
                },
                'score': result.score,
                'total_score': result.score,
                'total_questions': result.total_questions,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'result_text': result.result_text,
                'assertiveness_level': result.result_text,
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
                } if invitation else None,
                'total_attempts': len(result.score_history) if result.score_history else 1
            }
            
            history.append(basic_info)
            
            # Expandir historial con todos los intentos si existe score_history
            if result.score_history:
                for attempt in result.score_history:
                    expanded_info = basic_info.copy()
                    expanded_info.update({
                        'score': attempt['score'],
                        'total_score': attempt['score'],
                        'completed_at': attempt['completed_at'],
                        'attempt_number': attempt['attempt_number']
                    })
                    expanded_history.append(expanded_info)
            else:
                # Si no hay historial, agregar el resultado actual como primer intento
                expanded_info = basic_info.copy()
                expanded_info['attempt_number'] = 1
                expanded_history.append(expanded_info)
        
        # Ordenar historial expandido por fecha
        expanded_history.sort(key=lambda x: x['completed_at'])
        
        # Calcular estadísticas y datos de progreso basados en historial expandido
        statistics = {}
        progress_data = {}
        
        if expanded_history:
            # Agrupar evaluaciones por tipo de assessment
            evaluations_by_type = {}
            for h in expanded_history:
                assessment_title = h['assessment']['title']
                if assessment_title not in evaluations_by_type:
                    evaluations_by_type[assessment_title] = []
                evaluations_by_type[assessment_title].append(h)
            
            # Generar datos de progreso para el gráfico
            progress_data = {
                'labels': [],
                'datasets': []
            }
            
            # Crear labels basadas en cronología de intentos
            for i, eval_data in enumerate(expanded_history, 1):
                if eval_data['completed_at']:
                    date_obj = eval_data['completed_at'].split('T')[0]
                    attempt_num = eval_data.get('attempt_number', 1)
                    assessment_short = eval_data['assessment']['title'][:15] + "..." if len(eval_data['assessment']['title']) > 15 else eval_data['assessment']['title']
                    progress_data['labels'].append(f"{assessment_short} #{attempt_num}")
            
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
                data_points = []
                eval_type_index = 0
                
                for eval_general in expanded_history:
                    if eval_general['assessment']['title'] == assessment_type:
                        data_points.append(eval_general['score'])
                    else:
                        data_points.append(None)
                
                # Obtener color para este tipo de evaluación
                color = type_colors.get(assessment_type, '#6B8DA6')
                
                dataset = {
                    'label': assessment_type,
                    'data': data_points,
                    'borderColor': color,
                    'backgroundColor': f"{color}20",
                    'fill': False,
                    'tension': 0.1,
                    'spanGaps': False
                }
                progress_data['datasets'].append(dataset)
            
            # Estadísticas generales usando solo resultados únicos (no todos los intentos)
            scores = [h['score'] for h in history]  # Usar history original, no expanded
            total_attempts = sum([h['total_attempts'] for h in history])
            
            statistics = {
                'total_evaluations': len(history),
                'total_attempts': total_attempts,
                'average_score': round(sum(scores) / len(scores), 1),
                'latest_score': scores[-1] if scores else None,
                'improvement_trend': 'stable',
                'by_assessment_type': {}
            }
            
            # Estadísticas por tipo de evaluación
            for assessment_type, evaluations in evaluations_by_type.items():
                type_scores = [e['score'] for e in evaluations]
                latest_eval = max(evaluations, key=lambda x: x['completed_at']) if evaluations else None
                
                # Contar evaluaciones únicas de este tipo (no intentos)
                unique_evaluations = [h for h in history if h['assessment']['title'] == assessment_type]
                
                type_stats = {
                    'count': len(unique_evaluations),
                    'total_attempts': len(evaluations),
                    'average_score': round(sum(type_scores) / len(type_scores), 1),
                    'latest_score': latest_eval['score'] if latest_eval else None,
                    'latest_date': latest_eval['completed_at'] if latest_eval else None,
                    'improvement_trend': 'stable'
                }
                
                # Calcular tendencia para este tipo basado en intentos cronológicos
                if len(type_scores) >= 2:
                    if type_scores[-1] > type_scores[0]:
                        type_stats['improvement_trend'] = 'improving'
                    elif type_scores[-1] < type_scores[0]:
                        type_stats['improvement_trend'] = 'declining'
                    else:
                        type_stats['improvement_trend'] = 'stable'
                else:
                    type_stats['improvement_trend'] = 'insufficient_data'
                
                statistics['by_assessment_type'][assessment_type] = type_stats
        
        logger.debug(f"EVALUATION-HISTORY: Returning {len(history)} evaluations with {len(expanded_history)} total attempts")
        
        return jsonify({
            'success': True,
            'history': history,
            'expanded_history': expanded_history,  # Historial completo con todos los intentos
            'statistics': statistics,
            'progress_data': progress_data,
            'total': len(history)
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_evaluation_history: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo historial: {str(e)}'}), 500

@app.route('/api/coachee/assessment-history/<int:assessment_id>', methods=['GET'])
@coachee_session_required
def api_coachee_assessment_history(assessment_id):
    """
    Obtener historial completo de todos los intentos de una evaluación específica.
    Usa la tabla AssessmentHistory para tener el historial completo sin límites.
    """
    try:
        logger.info(f"🔍 ASSESSMENT-HISTORY: User {g.current_user.username} (ID: {g.current_user.id}) requesting history for assessment {assessment_id}")
        
        # Obtener assessment info
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        # Obtener historial completo desde AssessmentHistory
        history_entries = AssessmentHistory.query.filter_by(
            user_id=g.current_user.id,
            assessment_id=assessment_id
        ).order_by(AssessmentHistory.completed_at.asc()).all()
        
        # Formatear datos del historial
        history_data = []
        for entry in history_entries:
            # Formatear fecha con formato legible
            if entry.completed_at:
                # Formato: "03 Nov 2025 14:30"
                formatted_date = entry.completed_at.strftime('%d %b %Y %H:%M')
                date_only = entry.completed_at.strftime('%d/%m/%Y')
                time_only = entry.completed_at.strftime('%H:%M')
            else:
                formatted_date = 'N/A'
                date_only = 'N/A'
                time_only = 'N/A'
            
            history_data.append({
                'id': entry.id,
                'score': entry.score,  # Ya es porcentaje
                'score_percentage': entry.score,  # Explícito como porcentaje
                'total_questions': entry.total_questions,
                'completed_at': entry.completed_at.isoformat() if entry.completed_at else None,
                'formatted_date': formatted_date,
                'date_only': date_only,
                'time_only': time_only,
                'result_text': entry.result_text,
                'dimensional_scores': entry.dimensional_scores,
                'attempt_number': entry.attempt_number
            })
        
        # Calcular estadísticas (scores ya son porcentajes)
        statistics = {}
        if history_data:
            scores = [h['score'] for h in history_data]
            statistics = {
                'total_attempts': len(history_data),
                'first_score': round(scores[0], 2),
                'latest_score': round(scores[-1], 2),
                'best_score': round(max(scores), 2),
                'worst_score': round(min(scores), 2),
                'average_score': round(sum(scores) / len(scores), 2),
                'improvement': round(scores[-1] - scores[0], 2) if len(scores) > 1 else 0,
                'improvement_percentage': round(scores[-1] - scores[0], 2) if len(scores) > 1 else 0  # Ya es diferencia de porcentajes
            }
        
        # Datos para gráfico de progreso
        chart_data = {
            'labels': [h['formatted_date'] for h in history_data],  # Fecha legible completa
            'scores': [round(h['score'], 2) for h in history_data],  # Scores como porcentajes
            'dates': [h['date_only'] for h in history_data],  # Solo fecha para ordenar
            'times': [h['time_only'] for h in history_data],  # Solo hora
            'attempt_numbers': [h['attempt_number'] for h in history_data]  # Números de intento
        }
        
        logger.info(f"✅ ASSESSMENT-HISTORY: Returning {len(history_data)} attempts for assessment {assessment.title}")
        
        return jsonify({
            'success': True,
            'assessment': {
                'id': assessment.id,
                'title': assessment.title,
                'description': assessment.description
            },
            'history': history_data,
            'statistics': statistics,
            'chart_data': chart_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_assessment_history: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo historial: {str(e)}'}), 500

@app.route('/api/coachee/all-assessment-history', methods=['GET'])
@coachee_session_required
def api_coachee_all_assessment_history():
    """
    Obtener historial completo de TODAS las evaluaciones del coachee.
    Retorna datos agrupados por assessment_id para gráfico multi-línea.
    """
    try:
        logger.info(f"🔍 ALL-ASSESSMENT-HISTORY: User {g.current_user.username} (ID: {g.current_user.id}) requesting all assessment history")
        
        # Obtener TODO el historial del coachee desde AssessmentHistory
        history_entries = AssessmentHistory.query.filter_by(
            user_id=g.current_user.id
        ).order_by(AssessmentHistory.completed_at.desc()).all()  # 🔥 Ordenar descendente (último primero)
        
        if not history_entries:
            logger.info(f"📊 ALL-ASSESSMENT-HISTORY: No history found for user {g.current_user.id}")
            return jsonify({
                'success': True,
                'history': {},
                'total_evaluations': 0,
                'total_attempts': 0
            }), 200
        
        # Agrupar por assessment_id
        grouped_history = {}
        total_attempts = 0
        
        for entry in history_entries:
            assessment_id = entry.assessment_id
            
            # Obtener info del assessment si no existe en el grupo
            if assessment_id not in grouped_history:
                assessment = Assessment.query.get(assessment_id)
                if not assessment:
                    continue
                    
                grouped_history[assessment_id] = {
                    'title': assessment.title,
                    'description': assessment.description,
                    'data': []
                }
            
            # Formatear fecha
            if entry.completed_at:
                formatted_date = entry.completed_at.strftime('%d %b %Y %H:%M')
                date_only = entry.completed_at.strftime('%d/%m/%Y')
                time_only = entry.completed_at.strftime('%H:%M')
                iso_date = entry.completed_at.isoformat()
            else:
                formatted_date = 'N/A'
                date_only = 'N/A'
                time_only = 'N/A'
                iso_date = None
            
            # Agregar dato al grupo
            grouped_history[assessment_id]['data'].append({
                'id': entry.id,
                'score': entry.score,  # Ya es porcentaje
                'percentage': entry.score,  # Explícito
                'total_questions': entry.total_questions,
                'completed_at': iso_date,
                'formatted_date': formatted_date,
                'date_only': date_only,
                'time_only': time_only,
                'result_text': entry.result_text,
                'dimensional_scores': entry.dimensional_scores,
                'attempt_number': entry.attempt_number
            })
            
            total_attempts += 1
        
        # Calcular estadísticas generales
        all_scores = []
        for assessment_data in grouped_history.values():
            all_scores.extend([d['score'] for d in assessment_data['data']])
        
        statistics = {}
        if all_scores:
            statistics = {
                'total_evaluations': len(grouped_history),
                'total_attempts': total_attempts,
                'average_score': round(sum(all_scores) / len(all_scores), 2),
                'best_score': round(max(all_scores), 2),
                'worst_score': round(min(all_scores), 2)
            }
        
        # 🔥 ORDENAR datos dentro de cada grupo por fecha (descendente - último primero)
        for assessment_id, assessment_data in grouped_history.items():
            assessment_data['data'].sort(key=lambda x: x['completed_at'] if x['completed_at'] else '', reverse=True)
        
        logger.info(f"✅ ALL-ASSESSMENT-HISTORY: Returning {len(grouped_history)} evaluation types with {total_attempts} total attempts")
        
        return jsonify({
            'success': True,
            'history': grouped_history,
            'statistics': statistics,
            'total_evaluations': len(grouped_history),
            'total_attempts': total_attempts
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_all_assessment_history: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Error obteniendo historial: {str(e)}'}), 500

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
            logger.info(f"🔍 GENERATING RECOMMENDATIONS: assessment_title='{assessment.title}', score={result.score}, dimensional_scores={result.dimensional_scores}")
            recommendations = generate_recommendations(result.dimensional_scores, result.score, assessment.title)
            logger.info(f"📝 RECOMMENDATIONS GENERATED: {len(recommendations)} items - First 3: {recommendations[:3] if recommendations else 'None'}")
        elif result.score is not None:
            # Si no hay dimensional_scores, generar recomendaciones básicas
            logger.info(f"🔍 GENERATING BASIC RECOMMENDATIONS: assessment_title='{assessment.title}', score={result.score}")
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
@coach_session_required
def api_coach_evaluation_details(evaluation_id):
    """Obtener detalles específicos de una evaluación para coaches"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        # Verificar que es un coach
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden acceder.'}), 403
        
        # Obtener la evaluación específica
        result = AssessmentResult.query.filter_by(id=evaluation_id).first()
        
        if not result:
            return jsonify({'error': 'Evaluación no encontrada.'}), 404
        
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=result.user_id, coach_id=current_coach.id).first()
        
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

@app.route('/api/coachee/history-attempt-details/<int:history_id>', methods=['GET'])
@coachee_session_required
def api_coachee_history_attempt_details(history_id):
    """Obtener detalles específicos de un intento histórico desde AssessmentHistory"""
    try:
        logger.info(f"🔍 HISTORY-ATTEMPT-DETAILS: User {g.current_user.username} (ID: {g.current_user.id}) requesting history attempt {history_id}")
        
        # Obtener el intento específico del historial
        history_entry = AssessmentHistory.query.filter_by(
            id=history_id,
            user_id=g.current_user.id
        ).first()
        
        if not history_entry:
            logger.error(f"❌ HISTORY-ATTEMPT-DETAILS: History entry {history_id} not found for user {g.current_user.id}")
            return jsonify({'error': 'Intento de evaluación no encontrado.'}), 404
        
        # Obtener información del assessment
        assessment = Assessment.query.get(history_entry.assessment_id)
        
        if not assessment:
            logger.error(f"❌ HISTORY-ATTEMPT-DETAILS: Assessment {history_entry.assessment_id} not found")
            return jsonify({'error': 'Evaluación no encontrada.'}), 404
        
        # Generar recomendaciones basadas en los resultados históricos
        recommendations = []
        if history_entry.dimensional_scores and history_entry.score is not None:
            logger.info(f"🔍 GENERATING RECOMMENDATIONS FOR HISTORY: assessment_title='{assessment.title}', score={history_entry.score}, dimensional_scores={history_entry.dimensional_scores}")
            recommendations = generate_recommendations(history_entry.dimensional_scores, history_entry.score, assessment.title)
            logger.info(f"📝 HISTORY RECOMMENDATIONS GENERATED: {len(recommendations)} items")
        elif history_entry.score is not None:
            logger.info(f"🔍 GENERATING BASIC RECOMMENDATIONS FOR HISTORY: assessment_title='{assessment.title}', score={history_entry.score}")
            recommendations = generate_recommendations({}, history_entry.score, assessment.title)
        
        # Formatear fecha
        formatted_date = history_entry.completed_at.strftime('%d/%m/%Y %H:%M') if history_entry.completed_at else 'N/A'
        
        logger.info(f"✅ HISTORY-ATTEMPT-DETAILS: Returning details for attempt #{history_entry.attempt_number} of assessment '{assessment.title}'")
        logger.info(f"📊 SCORE DATA: score={history_entry.score}, is_percentage=True, assessment_type='{assessment.title}'")
        
        return jsonify({
            'success': True,
            'evaluation': {
                'id': history_entry.id,
                'assessment_id': history_entry.assessment_id,
                'assessment_title': assessment.title,
                'assessment': {
                    'id': history_entry.assessment_id,
                    'title': assessment.title,
                    'description': assessment.description
                },
                'score': history_entry.score,  # Ya es porcentaje en AssessmentHistory
                'is_percentage': True,  # 🔥 NUEVO: Indicar que el score ya es porcentaje
                'total_score': 100,  # Siempre 100 para porcentajes
                'total_questions': history_entry.total_questions,
                'completed_at': history_entry.completed_at.isoformat() if history_entry.completed_at else None,
                'formatted_date': formatted_date,
                'result_text': history_entry.result_text,
                'dimensional_scores': history_entry.dimensional_scores,
                'attempt_number': history_entry.attempt_number,
                'recommendations': recommendations,
                'coach': {
                    'name': history_entry.coach.full_name if history_entry.coach else 'Sin asignar',
                    'email': history_entry.coach.email if history_entry.coach else None
                } if history_entry.coach else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Error en api_coachee_history_attempt_details: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo detalles del intento: {str(e)}'}), 500

# ========== NUEVOS ENDPOINTS PARA GESTIÓN DE CITAS ==========

@app.route('/api/coach/self-schedule', methods=['POST'])
@coach_session_required
def api_coach_self_schedule():
    """Crear una actividad autoagendada para el coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['title', 'type', 'date', 'start_time', 'end_time']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Validar que la hora de fin sea después de la de inicio
        if data['start_time'] >= data['end_time']:
            return jsonify({'error': 'La hora de fin debe ser posterior a la hora de inicio'}), 400
        
        # Convertir strings a objetos date/time
        try:
            from datetime import datetime, date, time
            session_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
            start_time = datetime.strptime(data['start_time'], '%H:%M').time()
            end_time = datetime.strptime(data['end_time'], '%H:%M').time()
        except ValueError as e:
            return jsonify({'error': f'Formato de fecha/hora inválido: {str(e)}'}), 400
        
        # Buscar conflictos con sesiones existentes
        existing_sessions = CoachingSession.query.filter(
            and_(
                CoachingSession.coach_id == current_coach.id,
                CoachingSession.session_date == session_date,
                or_(
                    and_(CoachingSession.start_time < end_time, CoachingSession.end_time > start_time)
                )
            )
        ).first()
        
        if existing_sessions:
            return jsonify({'error': 'Hay un conflicto de horario con una sesión existente'}), 400
        
        # Crear la actividad autoagendada como una sesión especial
        self_activity = CoachingSession(
            coach_id=current_coach.id,
            coachee_id=None,  # None indica que es una actividad del coach
            session_date=session_date,
            start_time=start_time,
            end_time=end_time,
            status='confirmed',
            session_type='self_activity',
            notes=f"[ACTIVIDAD] {data['title']} - {data.get('description', '')}",
            activity_type=data['type'],
            activity_title=data['title'],
            activity_description=data.get('description', ''),
            is_recurring=data.get('recurring', False),
            created_at=get_santiago_now()
        )
        
        db.session.add(self_activity)
        
        # Si es recurrente, crear las próximas 4 semanas
        if data.get('recurring', False):
            from datetime import datetime, timedelta
            base_date = datetime.strptime(session_date, '%Y-%m-%d')
            
            for week in range(1, 5):  # Próximas 4 semanas
                future_date = base_date + timedelta(weeks=week)
                future_date_str = future_date.strftime('%Y-%m-%d')
                
                # Verificar que no hay conflictos futuros
                future_conflict = CoachingSession.query.filter(
                    and_(
                        CoachingSession.coach_id == current_coach.id,
                        CoachingSession.session_date == future_date_str,
                        or_(
                            and_(CoachingSession.start_time < end_time, CoachingSession.end_time > start_time)
                        )
                    )
                ).first()
                
                if not future_conflict:
                    future_activity = CoachingSession(
                        coach_id=current_coach.id,
                        coachee_id=None,
                        session_date=future_date_str,
                        start_time=start_time,
                        end_time=end_time,
                        status='confirmed',
                        session_type='self_activity',
                        notes=f"[ACTIVIDAD RECURRENTE] {data['title']} - {data.get('description', '')}",
                        activity_type=data['type'],
                        activity_title=data['title'],
                        activity_description=data.get('description', ''),
                        is_recurring=True,
                        created_at=get_santiago_now()
                    )
                    db.session.add(future_activity)
        
        db.session.commit()
        logger.info(f"Coach {current_coach.id} creó actividad autoagendada: {data['title']}")
        
        return jsonify({
            'success': True,
            'message': 'Tiempo bloqueado exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en self-schedule: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al bloquear tiempo: {str(e)}'}), 500

@app.route('/api/coach/create-direct-appointment', methods=['POST'])
@coach_session_required
def api_coach_create_direct_appointment():
    """Crear una cita directa para un coachee"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['coachee_id', 'session_type', 'date', 'start_time', 'end_time']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Validar que el coachee pertenece al coach
        coachee = User.query.filter_by(
            id=data['coachee_id'],
            coach_id=current_coach.id,
            role='coachee'
        ).first()
        
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no asignado a ti'}), 404
        
        # Validar que la hora de fin sea después de la de inicio
        if data['start_time'] >= data['end_time']:
            return jsonify({'error': 'La hora de fin debe ser posterior a la hora de inicio'}), 400
        
        # Convertir strings a objetos date/time
        try:
            from datetime import datetime, date, time
            session_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
            start_time = datetime.strptime(data['start_time'], '%H:%M').time()
            end_time = datetime.strptime(data['end_time'], '%H:%M').time()
        except ValueError as e:
            return jsonify({'error': f'Formato de fecha/hora inválido: {str(e)}'}), 400
        
        # Buscar conflictos con sesiones del coach
        coach_conflicts = CoachingSession.query.filter(
            and_(
                CoachingSession.coach_id == current_coach.id,
                CoachingSession.session_date == session_date,
                or_(
                    and_(CoachingSession.start_time < end_time, CoachingSession.end_time > start_time)
                )
            )
        ).first()
        
        if coach_conflicts:
            return jsonify({'error': 'Tienes un conflicto de horario en esa fecha y hora'}), 400
        
        # Buscar conflictos con sesiones del coachee
        coachee_conflicts = CoachingSession.query.filter(
            and_(
                CoachingSession.coachee_id == coachee.id,
                CoachingSession.session_date == session_date,
                or_(
                    and_(CoachingSession.start_time < end_time, CoachingSession.end_time > start_time)
                )
            )
        ).first()
        
        if coachee_conflicts:
            return jsonify({'error': f'{coachee.full_name} ya tiene una sesión en esa fecha y hora'}), 400
        
        # Crear la cita directa
        direct_appointment = CoachingSession(
            coach_id=current_coach.id,
            coachee_id=coachee.id,
            session_date=session_date,
            start_time=start_time,
            end_time=end_time,
            status='confirmed',
            session_type='direct_appointment',
            notes=data.get('session_notes', ''),
            created_by_coach=True,
            notification_message=data.get('notification_message', ''),
            created_at=get_santiago_now()
        )
        
        db.session.add(direct_appointment)
        db.session.commit()
        
        logger.info(f"Coach {current_coach.id} creó cita directa para coachee {coachee.id}")
        
        # TODO: Aquí se podría agregar lógica para enviar notificación al coachee
        # if data.get('send_notification', True):
        #     send_appointment_notification(coachee, direct_appointment, data.get('notification_message', ''))
        
        return jsonify({
            'success': True,
            'message': f'Cita directa creada para {coachee.full_name}'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en create-direct-appointment: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al crear cita directa: {str(e)}'}), 500

@app.route('/api/coach/self-scheduled-activities', methods=['GET'])
@coach_session_required
def api_coach_self_scheduled_activities():
    """Obtener actividades autoagendadas del coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Obtener actividades autoagendadas futuras (próximos 30 días)
        from datetime import datetime, timedelta
        today = get_santiago_today()
        future_limit = today + timedelta(days=30)
        
        activities = CoachingSession.query.filter(
            and_(
                CoachingSession.coach_id == current_coach.id,
                CoachingSession.coachee_id.is_(None),  # Sin coachee = actividad propia
                CoachingSession.session_type == 'self_activity',
                CoachingSession.session_date >= today.strftime('%Y-%m-%d'),
                CoachingSession.session_date <= future_limit.strftime('%Y-%m-%d')
            )
        ).order_by(CoachingSession.session_date, CoachingSession.start_time).all()
        
        activities_data = []
        for activity in activities:
            activities_data.append({
                'id': activity.id,
                'title': activity.activity_title or 'Actividad',
                'type': activity.activity_type or 'other',
                'date': activity.session_date,
                'start_time': activity.start_time,
                'end_time': activity.end_time,
                'description': activity.activity_description,
                'recurring': activity.is_recurring or False,
                'created_at': activity.created_at.isoformat() if activity.created_at else None
            })
        
        return jsonify({
            'success': True,
            'activities': activities_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error en self-scheduled-activities: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al obtener actividades: {str(e)}'}), 500

@app.route('/api/coach/upcoming-sessions', methods=['GET'])
@coach_session_required
def api_coach_upcoming_sessions():
    """Sesiones programadas para hoy y los próximos 7 días"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403

        from datetime import datetime, timedelta
        today = get_santiago_today()
        limit  = today + timedelta(days=7)

        sessions = CoachingSession.query.filter(
            and_(
                CoachingSession.coach_id == current_coach.id,
                CoachingSession.session_date >= today.strftime('%Y-%m-%d'),
                CoachingSession.session_date <= limit.strftime('%Y-%m-%d'),
                CoachingSession.session_type.in_(['coaching', 'direct_appointment', 'self_activity'])
            )
        ).order_by(CoachingSession.session_date, CoachingSession.start_time).all()

        result = []
        for s in sessions:
            coachee = User.query.get(s.coachee_id) if s.coachee_id else None
            date_obj = s.session_date if isinstance(s.session_date, date) else datetime.strptime(str(s.session_date), '%Y-%m-%d').date()
            result.append({
                'id':              s.id,
                'date':            date_obj.strftime('%Y-%m-%d'),
                'is_today':        date_obj == today,
                'start_time':      s.start_time.strftime('%H:%M') if s.start_time else None,
                'end_time':        s.end_time.strftime('%H:%M')   if s.end_time   else None,
                'coachee_id':      s.coachee_id or None,
                'coachee_name':    coachee.full_name if coachee else 'Coachee',
                'session_type':    s.session_type,
                'status':          s.status or 'scheduled',
                'title':           s.title or '',
                'activity_title':  s.activity_title or '',
                'notes':           s.notes or '',
            })

        return jsonify({'success': True, 'sessions': result}), 200

    except Exception as e:
        logger.error(f"Error en upcoming-sessions: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/coach/direct-appointments', methods=['GET'])
@coach_session_required
def api_coach_direct_appointments():
    """Obtener citas directas creadas por el coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Obtener citas directas recientes (últimos 30 días y próximos 30 días)
        from datetime import datetime, timedelta
        today = get_santiago_today()
        past_limit = today - timedelta(days=30)
        future_limit = today + timedelta(days=30)
        
        appointments = CoachingSession.query.filter(
            and_(
                CoachingSession.coach_id == current_coach.id,
                CoachingSession.session_type == 'direct_appointment',
                CoachingSession.session_date >= past_limit.strftime('%Y-%m-%d'),
                CoachingSession.session_date <= future_limit.strftime('%Y-%m-%d')
            )
        ).order_by(CoachingSession.session_date.desc(), CoachingSession.start_time.desc()).all()
        
        appointments_data = []
        for appointment in appointments:
            coachee = User.query.get(appointment.coachee_id)
            appointments_data.append({
                'id': appointment.id,
                'coachee_id': appointment.coachee_id,
                'coachee_name': coachee.full_name if coachee else 'Coachee eliminado',
                'session_type': appointment.session_type,
                'date': appointment.session_date,
                'start_time': appointment.start_time,
                'end_time': appointment.end_time,
                'session_notes': appointment.notes,
                'status': appointment.status,
                'created_at': appointment.created_at.isoformat() if appointment.created_at else None
            })
        
        return jsonify({
            'success': True,
            'appointments': appointments_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error en direct-appointments: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al obtener citas directas: {str(e)}'}), 500

@app.route('/api/coach/self-scheduled-activity/<int:activity_id>', methods=['DELETE'])
@coach_session_required
def api_coach_delete_self_scheduled_activity(activity_id):
    """Eliminar una actividad autoagendada"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Buscar la actividad
        activity = CoachingSession.query.filter(
            and_(
                CoachingSession.id == activity_id,
                CoachingSession.coach_id == current_coach.id,
                CoachingSession.coachee_id.is_(None),
                CoachingSession.session_type == 'self_activity'
            )
        ).first()
        
        if not activity:
            return jsonify({'error': 'Actividad no encontrada'}), 404
        
        # Si es recurrente, preguntar si eliminar todas las futuras también
        if activity.is_recurring:
            # Por ahora eliminamos solo la seleccionada
            # TODO: En el futuro se puede agregar lógica para eliminar todas las recurrentes
            pass
        
        db.session.delete(activity)
        db.session.commit()
        
        logger.info(f"Coach {current_coach.id} eliminó actividad autoagendada {activity_id}")
        
        return jsonify({
            'success': True,
            'message': 'Actividad eliminada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error eliminando actividad: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al eliminar actividad: {str(e)}'}), 500

# ===== ENDPOINTS DE DOCUMENTOS =====
import os
from werkzeug.utils import secure_filename
import uuid
from pathlib import Path

# Configuración para subida de archivos
UPLOAD_FOLDER = 'uploads/documents'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Configuración de AWS S3
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_S3_BUCKET = os.environ.get('AWS_S3_BUCKET')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
USE_S3 = all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET])

# Inicializar cliente S3 si está configurado
s3_client = None
if USE_S3:
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        logger.info(f"✅ Cliente S3 inicializado correctamente. Bucket: {AWS_S3_BUCKET}")
    except Exception as e:
        logger.error(f"❌ Error inicializando cliente S3: {str(e)}")
        USE_S3 = False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_upload_folder():
    """Asegurar que existe la carpeta de uploads (solo para modo local)"""
    if not USE_S3 and not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

def upload_file_to_s3(file, filename):
    """Subir archivo a S3"""
    try:
        s3_key = f"documents/{filename}"
        s3_client.upload_fileobj(
            file,
            AWS_S3_BUCKET,
            s3_key,
            ExtraArgs={
                'ContentType': file.content_type or 'application/octet-stream',
                'ContentDisposition': f'inline; filename="{filename}"'
            }
        )
        # Generar URL del archivo
        file_url = f"https://{AWS_S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
        logger.info(f"✅ Archivo subido a S3: {file_url}")
        return file_url
    except ClientError as e:
        logger.error(f"❌ Error subiendo archivo a S3: {str(e)}")
        raise

def download_file_from_s3(s3_key):
    """Descargar archivo desde S3"""
    try:
        response = s3_client.get_object(Bucket=AWS_S3_BUCKET, Key=s3_key)
        return response['Body'].read()
    except ClientError as e:
        logger.error(f"❌ Error descargando archivo desde S3: {str(e)}")
        raise

@app.route('/api/coach/upload-document', methods=['POST'])
@coach_session_required
def api_coach_upload_document():
    """Endpoint para subir documentos"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que se envió un archivo
        if 'file' not in request.files:
            return jsonify({'error': 'No se envió ningún archivo'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        # Validar archivo
        if not allowed_file(file.filename):
            return jsonify({'error': 'Tipo de archivo no permitido'}), 400
        
        # Obtener datos del formulario
        coachee_id = request.form.get('coachee_id')
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        priority = request.form.get('priority', 'normal')
        notify_coachee = request.form.get('notify_coachee') == 'true'
        
        # Validar datos requeridos
        if not coachee_id or not title or not category:
            return jsonify({'error': 'Faltan datos requeridos'}), 400
        
        # Verificar que el coachee existe y pertenece al coach
        coachee = User.query.filter_by(id=coachee_id, role='coachee').first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado'}), 404
        
        # Verificar relación coach-coachee (esto podría requerir una tabla de relaciones)
        # Por ahora asumimos que cualquier coach puede asignar a cualquier coachee
        
        # Validar tamaño del archivo
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': f'El archivo es demasiado grande. Máximo {MAX_FILE_SIZE // (1024*1024)}MB'}), 400
        
        # Preparar directorio de subida (solo si no usamos S3)
        if not USE_S3:
            ensure_upload_folder()
        
        # Generar nombre único para el archivo
        original_filename = file.filename
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        
        # Subir archivo a S3 o guardar localmente
        if USE_S3:
            # Subir a S3
            file_url = upload_file_to_s3(file, unique_filename)
            file_path = file_url  # Guardar URL de S3
        else:
            # Guardar localmente con ruta absoluta
            file_path = os.path.abspath(os.path.join(UPLOAD_FOLDER, unique_filename))
            file.save(file_path)
        
        # Crear registro de documento
        document = Document(
            coach_id=current_coach.id,
            coachee_id=coachee_id,
            title=title,
            description=description,
            category=category,
            priority=priority,
            notify_coachee=notify_coachee
        )
        
        db.session.add(document)
        db.session.flush()  # Para obtener el ID del documento
        
        # Crear registro del archivo
        document_file = DocumentFile(
            document_id=document.id,
            filename=unique_filename,
            original_filename=original_filename,
            file_path=file_path,
            file_size=file_size,
            mime_type=file.content_type or 'application/octet-stream'
        )
        
        db.session.add(document_file)
        db.session.flush()  # Para obtener el ID del archivo
        
        # NUEVO: Crear también un registro en la tabla Content para que aparezca en "Contenido Asignado"
        # Usar endpoint de coachee para que funcione independientemente de la sesión del coach
        content_url = f"/api/coachee/documents/{document.id}/files/{document_file.id}/preview"
        content = Content(
            coach_id=current_coach.id,
            coachee_id=coachee_id,
            title=title,
            description=description,
            content_type='document',
            content_url=content_url,
            assigned_at=datetime.utcnow()
        )
        
        db.session.add(content)
        db.session.commit()
        
        logger.info(f"Coach {current_coach.id} subió documento {document.id} para coachee {coachee_id} y creó contenido {content.id}")
        
        return jsonify({
            'success': True,
            'message': 'Documento subido exitosamente',
            'document_id': document.id,
            'content_id': content.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error subiendo documento: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al subir documento: {str(e)}'}), 500

@app.route('/api/coach/document-stats', methods=['GET'])
@coach_session_required
def api_coach_document_stats():
    """Obtener estadísticas de documentos subidos por el coach"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Contar documentos por tipo
        stats = db.session.query(
            DocumentFile.mime_type,
            db.func.count(DocumentFile.id)
        ).join(Document).filter(
            Document.coach_id == current_coach.id,
            Document.is_active == True
        ).group_by(DocumentFile.mime_type).all()
        
        # Organizar estadísticas
        pdf_count = 0
        image_count = 0
        doc_count = 0
        
        for mime_type, count in stats:
            if 'pdf' in mime_type.lower():
                pdf_count += count
            elif any(img_type in mime_type.lower() for img_type in ['image', 'jpeg', 'jpg', 'png', 'gif']):
                image_count += count
            elif any(doc_type in mime_type.lower() for doc_type in ['document', 'word', 'msword']):
                doc_count += count
        
        return jsonify({
            'success': True,
            'stats': {
                'pdf': pdf_count,
                'images': image_count,
                'documents': doc_count
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de documentos: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al obtener estadísticas: {str(e)}'}), 500

@app.route('/api/coachee/profile', methods=['GET'])
@coachee_session_required
def api_coachee_profile():
    """Obtener perfil del coachee actual"""
    try:
        # Usar g.current_user del decorador (no Flask-Login current_user)
        coachee = g.current_user
        
        # Obtener información del coach asignado
        coach = None
        if coachee.coach_id:
            coach = User.query.get(coachee.coach_id)
        
        # Obtener estadísticas básicas
        total_evaluations = AssessmentResult.query.filter_by(user_id=coachee.id).count()
        
        return jsonify({
            'success': True,
            'profile': {
                'id': coachee.id,
                'username': coachee.username,
                'full_name': coachee.full_name,
                'email': coachee.email,
                'role': coachee.role,
                'avatar_url': coachee.avatar_url if hasattr(coachee, 'avatar_url') else None,
                'created_at': coachee.created_at.isoformat() if hasattr(coachee, 'created_at') and coachee.created_at else None,
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

@app.route('/api/coachee/dashboard-init', methods=['GET'])
@coachee_session_required
def api_coachee_dashboard_init():
    """
    Endpoint optimizado que retorna TODOS los datos necesarios para inicializar el dashboard coachee
    en una sola llamada, reduciendo latencia de red en producción.
    
    Retorna:
    - profile: Datos del perfil del coachee
    - evaluations: Evaluaciones disponibles y completadas
    - pending_tasks_count: Número de tareas pendientes
    - completed_evaluations_count: Número de evaluaciones completadas
    """
    try:
        current_coachee = g.current_user
        
        if current_coachee.role != 'coachee':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        logger.info(f"🚀 DASHBOARD-INIT: Loading all data for coachee {current_coachee.username}")
        
        # 1. PROFILE DATA
        coach = None
        if current_coachee.coach_id:
            coach = User.query.get(current_coachee.coach_id)
        
        total_evaluations = AssessmentResult.query.filter_by(
            user_id=current_coachee.id
        ).count()
        
        profile_data = {
            'id': current_coachee.id,
            'username': current_coachee.username,
            'full_name': current_coachee.full_name,
            'email': current_coachee.email,
            'role': current_coachee.role,
            'avatar_url': current_coachee.avatar_url if hasattr(current_coachee, 'avatar_url') else None,
            'created_at': current_coachee.created_at.isoformat() if hasattr(current_coachee, 'created_at') and current_coachee.created_at else None,
            'coach': {
                'id': coach.id if coach else None,
                'name': coach.full_name if coach else None,
                'email': coach.email if coach else None
            } if coach else None,
            'stats': {
                'total_evaluations_completed': total_evaluations
            }
        }
        
        # 2. EVALUATIONS DATA (disponibles y completadas)
        # Evaluaciones completadas
        completed_results = AssessmentResult.query.filter(
            AssessmentResult.user_id == current_coachee.id,
            AssessmentResult.completed_at.isnot(None)
        ).order_by(AssessmentResult.completed_at.desc()).limit(10).all()
        
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
                'dimensional_scores': result.dimensional_scores
            })
        
        # Evaluaciones disponibles (asignadas por tareas)
        assigned_tasks = Task.query.filter_by(
            coachee_id=current_coachee.id,
            is_active=True,
            category='evaluation'
        ).all()
        
        available_evaluations = {}
        for task in assigned_tasks:
            # Parsear título de la tarea para obtener assessment_id
            if 'assessment_id:' in task.description:
                try:
                    assessment_id = int(task.description.split('assessment_id:')[1].split()[0])
                    assessment = Assessment.query.get(assessment_id)
                    if assessment and assessment.is_active:
                        available_evaluations[assessment.category] = {
                            'id': assessment.id,
                            'title': assessment.title,
                            'description': assessment.description,
                            'category': assessment.category,
                            'task_id': task.id
                        }
                except (ValueError, IndexError):
                    continue
        
        # 3. TASKS STATS
        tasks = Task.query.filter(
            Task.coachee_id == current_coachee.id,
            Task.is_active == True,
            Task.category != 'evaluation'
        ).all()
        
        pending_tasks = 0
        current_date = date.today()
        
        for task in tasks:
            latest_progress = TaskProgress.query.filter_by(task_id=task.id)\
                .order_by(TaskProgress.created_at.desc()).first()
            
            if latest_progress and latest_progress.status in ['pending', 'in_progress']:
                pending_tasks += 1
        
        # 4. RESPONSE COMBINADA
        response = {
            'success': True,
            'profile': profile_data,
            'evaluations': {
                'available': available_evaluations,
                'completed': completed_evaluations,
                'total_available': len(available_evaluations),
                'total_completed': len(completed_evaluations)
            },
            'stats': {
                'pending_tasks_count': pending_tasks,
                'completed_evaluations_count': len(completed_evaluations)
            }
        }
        
        logger.info(f"✅ DASHBOARD-INIT: Returning all data in single response for coachee")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"❌ DASHBOARD-INIT: Error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/coachee/dashboard-summary', methods=['GET'])
@coachee_session_required
def api_coachee_dashboard_summary():
    """Obtener resumen para el dashboard del coachee (LEGACY - mantener para compatibilidad)"""
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
                    'avatar_url': current_user.avatar_url,
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
@coachee_session_required
def api_coachee_validate_visibility():
    """Validar que las evaluaciones sean visibles para el coachee actual"""
    try:
        # Usar g.current_user del decorador (no Flask-Login current_user)
        coachee = g.current_user
        
        # Obtener assessment_id específico si se proporciona
        assessment_id = request.args.get('assessment_id', type=int)
        
        # Ejecutar validación
        validation_result = validate_evaluation_visibility(coachee.id, assessment_id)
        
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
            'details': {'user_id': g.current_user.id}
        }), 500

@app.route('/api/admin/validate-coachee-visibility/<int:coachee_id>', methods=['GET'])
@either_session_required
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
        current_user = g.current_user
        
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
        
        new_status = data.get('status', 'in_progress')
        
        # Crear nueva entrada de progreso
        progress_entry = TaskProgress(
            task_id=task_id,
            status=new_status,
            progress_percentage=data.get('progress_percentage', 0),
            notes=data.get('notes', ''),
            updated_by=current_user.id
        )
        
        db.session.add(progress_entry)
        
        # GAMIFICACIÓN: Otorgar puntos cuando se completa la tarea (Etapa 5-6)
        points_awarded = 0
        level_up = False
        new_level_info = None
        
        if new_status == 'completed':
            app.logger.info(f"🎮 GAMIFICACIÓN: Tarea {task_id} completada por coachee {current_user.id}")
            
            # Buscar configuración de puntos para esta tarea
            points_config = db.session.execute(
                text("""
                    SELECT difficulty_level, base_points 
                    FROM task_points_config 
                    WHERE task_id = :task_id
                """),
                {'task_id': task_id}
            ).fetchone()
            
            if points_config:
                difficulty = points_config[0]
                points_value = points_config[1]
                
                app.logger.info(f"🎮 Configuración encontrada: {difficulty} = {points_value} puntos")
                
                # Crear transacción de puntos
                db.session.execute(
                    text("""
                        INSERT INTO point_transactions 
                        (coachee_id, task_id, points_earned, transaction_type, description, created_at)
                        VALUES (:coachee_id, :task_id, :points, 'task_completed', :description, :created_at)
                    """),
                    {
                        'coachee_id': current_user.id,
                        'task_id': task_id,
                        'points': points_value,
                        'description': f'Tarea completada: {task.title} (Dificultad: {difficulty})',
                        'created_at': datetime.utcnow()
                    }
                )
                app.logger.info(f"✅ Transacción registrada: +{points_value} puntos")
                
                # Obtener puntos actuales del coachee
                current_points_row = db.session.execute(
                    text("SELECT total_points, current_level FROM coachee_points WHERE coachee_id = :coachee_id"),
                    {'coachee_id': current_user.id}
                ).fetchone()
                
                if current_points_row:
                    old_points = current_points_row[0]
                    old_level = current_points_row[1]
                    new_points = old_points + points_value
                    
                    # Actualizar puntos
                    db.session.execute(
                        text("""
                            UPDATE coachee_points 
                            SET total_points = :new_points, updated_at = :updated_at
                            WHERE coachee_id = :coachee_id
                        """),
                        {
                            'new_points': new_points,
                            'updated_at': datetime.utcnow(),
                            'coachee_id': current_user.id
                        }
                    )
                    app.logger.info(f"✅ Puntos actualizados: {old_points} → {new_points}")
                    
                    # Recalcular nivel
                    new_level_row = db.session.execute(
                        text("""
                            SELECT level_number, level_name, icon_class, color_hex 
                            FROM levels_system 
                            WHERE points_required <= :points 
                            ORDER BY points_required DESC 
                            LIMIT 1
                        """),
                        {'points': new_points}
                    ).fetchone()
                    
                    if new_level_row:
                        new_level = new_level_row[0]
                        
                        if new_level > old_level:
                            # ¡Level up!
                            level_up = True
                            new_level_info = {
                                'level_number': new_level_row[0],
                                'level_name': new_level_row[1],
                                'icon_class': new_level_row[2],
                                'color_hex': new_level_row[3]
                            }
                            
                            # Actualizar nivel
                            db.session.execute(
                                text("""
                                    UPDATE coachee_points 
                                    SET current_level = :new_level
                                    WHERE coachee_id = :coachee_id
                                """),
                                {
                                    'new_level': new_level,
                                    'coachee_id': current_user.id
                                }
                            )
                            app.logger.info(f"🎉 ¡LEVEL UP! Nivel {old_level} → {new_level}: {new_level_info['level_name']}")
                        else:
                            app.logger.info(f"📊 Mismo nivel: {new_level}")
                    
                    points_awarded = points_value
                else:
                    app.logger.warning(f"⚠️ No se encontró registro en coachee_points para coachee {current_user.id}")
            else:
                app.logger.warning(f"⚠️ No hay configuración de puntos para tarea {task_id}")
        
        db.session.commit()
        
        response_data = {
            'success': True,
            'message': 'Progreso actualizado exitosamente'
        }
        
        # Añadir información de gamificación a la respuesta
        if points_awarded > 0:
            response_data['gamification'] = {
                'points_awarded': points_awarded,
                'level_up': level_up,
                'new_level': new_level_info
            }
        
        return jsonify(response_data), 200
        
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
            'id': g.current_user.id,
            'full_name': g.current_user.full_name,
            'email': g.current_user.email,
            'username': g.current_user.username,
            'avatar_url': g.current_user.avatar_url,
            'role': g.current_user.role,
            'created_at': g.current_user.created_at.isoformat() if hasattr(g.current_user, 'created_at') and g.current_user.created_at else None
        }
        
        # Agregar información específica según el rol
        if g.current_user.role == 'coachee':
            coach = None
            if g.current_user.coach_id:
                coach = User.query.get(g.current_user.coach_id)
            
            profile_data['coach'] = {
                'id': coach.id if coach else None,
                'name': coach.full_name if coach else None,
                'email': coach.email if coach else None
            } if coach else None
            
            # Estadísticas del coachee
            profile_data['stats'] = {
                'total_evaluations': AssessmentResult.query.filter_by(user_id=g.current_user.id).count()
            }
            
        elif g.current_user.role == 'coach':
            # Estadísticas del coach
            coachees_count = User.query.filter_by(coach_id=g.current_user.id, role='coachee').count()
            total_evaluations = AssessmentResult.query.filter_by(coach_id=g.current_user.id).count()
            
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

# API endpoints para perfil de coachee
@app.route('/api/coachee/upload-avatar', methods=['POST'])
@coachee_session_required
def api_coachee_upload_avatar():
    """Upload avatar para coachee"""
    try:
        if 'avatar' not in request.files:
            return jsonify({'success': False, 'error': 'No se recibió ningún archivo'}), 400
        
        file = request.files['avatar']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No se seleccionó ningún archivo'}), 400
        
        # Validar tipo de archivo
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Tipo de archivo no permitido'}), 400
        
        # Generar nombre único para el archivo
        unique_filename = f"{g.current_user.id}_{uuid.uuid4().hex[:8]}.{file_ext}"
        
        # Guardar en el directorio static/avatars
        avatars_dir = os.path.join(app.root_path, 'static', 'avatars')
        os.makedirs(avatars_dir, exist_ok=True)
        
        file_path = os.path.join(avatars_dir, unique_filename)
        file.save(file_path)
        
        # Actualizar URL del avatar en la base de datos
        avatar_url = f"/static/avatars/{unique_filename}"
        g.current_user.avatar_url = avatar_url
        db.session.commit()
        
        logger.info(f"Avatar uploaded for user {g.current_user.id}: {avatar_url}")
        
        return jsonify({
            'success': True,
            'avatar_url': avatar_url
        }), 200
        
    except Exception as e:
        logger.error(f"Error uploading avatar: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Endpoint de cambio de contraseña de coachee eliminado (duplicado) - usar el de línea 3954

@app.route('/api/coachee/set-avatar-url', methods=['POST'])
@coachee_session_required
def api_coachee_set_avatar_url():
    """Establecer URL de avatar predefinido para coachee"""
    try:
        data = request.get_json()
        
        avatar_url = data.get('avatar_url')
        
        if not avatar_url:
            return jsonify({'success': False, 'error': 'URL del avatar es requerida'}), 400
        
        # Validar URLs de S3 (si es una URL de AWS)
        if 's3' in avatar_url.lower() and 'amazonaws.com' in avatar_url.lower():
            is_valid, error_msg = validate_s3_url(avatar_url)
            if not is_valid:
                logger.warning(f"Invalid S3 URL rejected for user {g.current_user.id}: {avatar_url}")
                log_suspicious_activity(
                    description=f'Attempted to set invalid S3 URL as avatar: {error_msg}',
                    user_id=g.current_user.id,
                    username=g.current_user.username,
                    severity='warning'
                )
                return jsonify({'success': False, 'error': f'URL de S3 no válida: {error_msg}'}), 400
        else:
            # Validar que la URL sea de un servicio permitido (avatares externos)
            allowed_domains = ['pravatar.cc', 'ui-avatars.com', 'robohash.org', 'i.pravatar.cc']
            from urllib.parse import urlparse
            parsed_url = urlparse(avatar_url)
            
            if not any(domain in parsed_url.netloc for domain in allowed_domains):
                # Si es una URL local (empieza con /static/), también permitirla
                if not avatar_url.startswith('/static/'):
                    return jsonify({'success': False, 'error': 'URL de avatar no permitida'}), 400
        
        # Actualizar URL del avatar en la base de datos
        g.current_user.avatar_url = avatar_url
        db.session.commit()
        
        logger.info(f"Avatar URL set for user {g.current_user.id}: {avatar_url}")
        
        return jsonify({
            'success': True,
            'avatar_url': avatar_url
        }), 200
        
    except Exception as e:
        logger.error(f"Error setting avatar URL: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoints para contenido/videos
@app.route('/api/coachee/content', methods=['GET'])
@either_session_required
def api_coachee_get_content():
    """Obtener contenido asignado al coachee actual"""
    try:
        coachee = get_current_coachee()
        if not coachee:
            return jsonify({'error': 'Usuario coachee no encontrado'}), 404
        
        # Obtener contenido asignado a este coachee
        content_items = Content.query.filter_by(
            coachee_id=coachee.id,
            is_active=True
        ).order_by(Content.assigned_at.desc()).all()
        
        content_list = []
        for content in content_items:
            coach = User.query.get(content.coach_id)
            
            # Mapear tipos de contenido a categorías estándar
            content_type = content.content_type.lower() if content.content_type else 'video'
            normalized_type = 'video'  # Por defecto video
            
            if content_type in ['document', 'pdf', 'doc', 'docx']:
                normalized_type = 'document'
            elif content_type in ['video', 'youtube', 'vimeo', 'instagram']:
                normalized_type = 'video'
            
            # Extraer video_id y detectar plataforma si es un video
            video_id = None
            video_platform = None
            if normalized_type == 'video' and content.content_url:
                import re
                
                # Detectar Instagram
                instagram_patterns = [
                    r'instagram\.com\/(?:p|reel|tv)\/([A-Za-z0-9_-]+)',
                ]
                for pattern in instagram_patterns:
                    match = re.search(pattern, content.content_url)
                    if match:
                        video_id = match.group(1)
                        video_platform = 'instagram'
                        break
                
                # Detectar YouTube si no es Instagram
                if not video_id:
                    youtube_patterns = [
                        r'(?:youtube\.com\/watch\?v=|youtu\.be\/)([^&\n?#]+)',
                        r'youtube\.com\/embed\/([^&\n?#]+)',
                    ]
                    for pattern in youtube_patterns:
                        match = re.search(pattern, content.content_url)
                        if match:
                            video_id = match.group(1)
                            video_platform = 'youtube'
                            break
            
            content_data = {
                'id': content.id,
                'title': content.title,
                'description': content.description,
                'type': normalized_type,  # 'video' o 'document'
                'content_type': content.content_type,  # Mantener original por compatibilidad
                'content_url': content.content_url,
                'file_path': content.content_url,  # Alias para documentos
                'video_id': video_id,  # ID extraído de YouTube o Instagram
                'video_platform': video_platform,  # 'youtube' o 'instagram'
                'youtube_id': video_id if video_platform == 'youtube' else None,  # Mantener por compatibilidad
                'thumbnail_url': content.thumbnail_url,
                'duration': content.duration,
                'is_viewed': content.is_viewed,
                'viewed_at': content.viewed_at.isoformat() if content.viewed_at else None,
                'created_at': content.assigned_at.isoformat() if content.assigned_at else None,
                'assigned_at': content.assigned_at.isoformat() if content.assigned_at else None,
                'coach_name': coach.full_name if coach else 'Coach no encontrado',
                'coach_avatar_url': coach.avatar_url if coach and coach.avatar_url else None
            }
            content_list.append(content_data)
        
        return jsonify({
            'success': True,
            'content': content_list
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_get_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo contenido: {str(e)}'}), 500

@app.route('/api/coachee/content/<int:content_id>/mark-viewed', methods=['POST'])
@either_session_required
def api_coachee_mark_content_viewed(content_id):
    """Marcar contenido como visto"""
    try:
        coachee = get_current_coachee()
        if not coachee:
            return jsonify({'error': 'Usuario coachee no encontrado'}), 404
        
        # Verificar que el contenido pertenece al coachee
        content = Content.query.filter_by(
            id=content_id,
            coachee_id=coachee.id,
            is_active=True
        ).first()
        
        if not content:
            return jsonify({'error': 'Contenido no encontrado'}), 404
        
        # Marcar como visto
        content.mark_as_viewed()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Contenido marcado como visto'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coachee_mark_content_viewed: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error marcando contenido como visto: {str(e)}'}), 500

@app.route('/api/coach/content', methods=['POST'])
@coach_session_required
def api_coach_assign_content():
    """Publicar contenido: biblioteca, coachee, y/o comunidad"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden publicar contenido.'}), 403
        
        data = request.get_json()
        
        # Validar campos requeridos mínimos
        required_fields = ['title', 'content_url']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Obtener opciones de publicación
        coachee_id = data.get('coachee_id')
        save_to_library = data.get('save_to_library', False)
        # share_with_community = data.get('shared_with_community', False)  # DESHABILITADO: columnas no existen en producción
        # community_id = data.get('community_id')  # DESHABILITADO: columnas no existen en producción
        
        # Validar que al menos se seleccione una opción
        if not coachee_id and not save_to_library:
            return jsonify({'error': 'Debes seleccionar al menos una opción: biblioteca o coachee'}), 400
        
        # Si se especifica coachee, verificar que pertenezca al coach
        if coachee_id:
            coachee = User.query.filter_by(
                id=coachee_id,
                coach_id=current_coach.id,
                role='coachee'
            ).first()
            
            if not coachee:
                return jsonify({'error': 'Coachee no encontrado o no pertenece a este coach'}), 404
            
            # Verificar duplicados solo si se asigna a coachee
            logger.info(f"🔍 DUPLICATE-CHECK: Verificando duplicados para coach_id={current_coach.id}, coachee_id={coachee_id}, title='{data['title']}', url='{data['content_url']}'")
            
            existing_content = Content.query.filter_by(
                coach_id=current_coach.id,
                coachee_id=coachee_id,
                title=data['title'],
                content_url=data['content_url'],
                is_active=True
            ).first()
            
            if existing_content:
                logger.warning(f"⚠️ DUPLICATE-FOUND: Content ID {existing_content.id} ya existe para este coachee")
                return jsonify({
                    'error': 'Ya existe contenido con este título y URL para este coachee',
                    'existing_content_id': existing_content.id
                }), 409
        
        # Validar comunidad si se especifica
        # DESHABILITADO: Funcionalidad de comunidades requiere migración de BD
        # if share_with_community and community_id:
        #     community = CoachCommunity.query.filter_by(id=community_id, is_active=True).first()
        #     if not community:
        #         return jsonify({'error': 'Comunidad no encontrada'}), 404
        #     
        #     membership = CommunityMembership.query.filter_by(
        #         community_id=community_id,
        #         coach_id=current_coach.id,
        #         is_active=True
        #     ).first()
        #     
        #     if not membership:
        #         return jsonify({'error': 'No eres miembro de esta comunidad'}), 403
        
        logger.info(f"✅ PUBLICANDO: Creando contenido para coach {current_coach.id}")
        
        # Crear nuevo contenido
        # Si no hay coachee_id, se guarda como biblioteca (coachee_id = NULL)
        content = Content(
            coach_id=current_coach.id,
            coachee_id=coachee_id if coachee_id else None,
            title=data['title'],
            description=data.get('description', ''),
            content_type=data.get('content_type', 'video'),
            content_url=data['content_url'],
            thumbnail_url=data.get('thumbnail_url'),
            duration=data.get('duration')
            # community_id y shared_with_community removidos - columnas no existen en producción
        )
        
        db.session.add(content)
        db.session.commit()
        
        # Construir mensaje de éxito
        destinations = []
        if save_to_library or not coachee_id:
            destinations.append('biblioteca')
        if coachee_id:
            destinations.append('coachee')
        # if share_with_community:  # DESHABILITADO
        #     destinations.append('comunidad')
        
        message = f'Contenido publicado en: {", ".join(destinations)}'
        
        return jsonify({
            'success': True,
            'message': message,
            'content_id': content.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coach_assign_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error publicando contenido: {str(e)}'}), 500

@app.route('/api/coach/content', methods=['GET'])
@coach_session_required
def api_coach_get_assigned_content():
    """Obtener contenido asignado por el coach con filtros"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver contenido asignado.'}), 403
        
        # Obtener parámetros de filtro
        coachee_filter = request.args.get('coachee_id', type=int)
        view_mode = request.args.get('view_mode', 'unique')  # 'all', 'unique' - Por defecto 'unique' para agrupar contenido
        
        # Query base
        query = Content.query.filter_by(coach_id=current_coach.id, is_active=True)
        
        # Aplicar filtro de coachee si se especifica
        if coachee_filter:
            query = query.filter_by(coachee_id=coachee_filter)
        
        # LOG: Ver TODOS los Content antes de aplicar ORDER BY
        all_content_in_db = Content.query.filter_by(coach_id=current_coach.id).all()
        logger.info(f"🔍 DEBUG-QUERY: Total Content para coach {current_coach.id} en DB (sin filtros): {len(all_content_in_db)}")
        for c in all_content_in_db:
            logger.info(f"  - ID={c.id}, Type={c.content_type}, Title={c.title}, Active={c.is_active}")
        
        # Obtener contenido ordenado por fecha de asignación
        content_items = query.order_by(Content.assigned_at.desc()).all()
        
        logger.info(f"🔍 COACH-CONTENT: Coach {current_coach.id} solicitando contenido - view_mode: {view_mode}, coachee_filter: {coachee_filter}")
        logger.info(f"📊 RAW-DATA: Encontrados {len(content_items)} items de contenido (después del filtro is_active=True)")
        
        # Log detalles de los primeros items para debug
        for i, item in enumerate(content_items[:3]):
            logger.info(f"📝 ITEM-{i}: ID={item.id}, Title='{item.title}', Coachee={item.coachee_id}, URL='{item.content_url}'")
        
        if len(content_items) > 3:
            logger.info(f"... y {len(content_items) - 3} items adicionales")
        
        if view_mode == 'unique':
            # Agrupar contenido único por título y URL
            unique_content = {}
            for content in content_items:
                key = f"{content.title}_{content.content_url}"
                if key not in unique_content:
                    unique_content[key] = {
                        'content': content,
                        'assignments': [],
                        'total_viewed': 0,
                        'total_assigned': 0
                    }
                
                coachee = User.query.get(content.coachee_id)
                assignment_data = {
                    'id': content.id,
                    'coachee_name': coachee.full_name if coachee else 'Coachee no encontrado',
                    'coachee_email': coachee.email if coachee else 'Email no disponible',
                    'is_viewed': content.is_viewed,
                    'viewed_at': content.viewed_at.isoformat() if content.viewed_at else None,
                    'assigned_at': content.assigned_at.isoformat() if content.assigned_at else None
                }
                
                unique_content[key]['assignments'].append(assignment_data)
                unique_content[key]['total_assigned'] += 1
                if content.is_viewed:
                    unique_content[key]['total_viewed'] += 1
            
            # Convertir a lista para respuesta
            content_list = []
            for key, data in unique_content.items():
                content = data['content']
                
                # Transformar URL de documento para que funcione con sesión de coach
                content_url = content.content_url
                if content.content_type == 'document' and '/api/coachee/documents/' in content_url:
                    import re
                    match = re.search(r'/api/coachee/documents/(\d+)/', content_url)
                    if match:
                        document_id = match.group(1)
                        content_url = f"/api/coach/documents/{document_id}/view"
                        logger.info(f"✅ TRANSFORM-UNIQUE: Content ID {content.id} - Transformado a {content_url}")
                
                content_data = {
                    'id': content.id,
                    'title': content.title,
                    'description': content.description,
                    'content_type': content.content_type,
                    'content_url': content_url,
                    'thumbnail_url': content.thumbnail_url,
                    'duration': content.duration,
                    'assigned_at': content.assigned_at.isoformat() if content.assigned_at else None,
                    'assignments': data['assignments'],
                    'total_assigned': data['total_assigned'],
                    'total_viewed': data['total_viewed'],
                    'total_pending': data['total_assigned'] - data['total_viewed'],
                    'view_mode': 'unique'
                }
                content_list.append(content_data)
        
        else:
            # Vista normal - mostrar todas las asignaciones
            content_list = []
            for content in content_items:
                coachee = User.query.get(content.coachee_id)
                
                # Transformar URL de documento para que funcione con sesión de coach
                content_url = content.content_url
                logger.info(f"🔎 TRANSFORM-CHECK: Content ID={content.id}, Type={content.content_type}, URL original={content_url}")
                
                if content.content_type == 'document' and '/api/coachee/documents/' in content_url:
                    # Extraer document_id de la URL del coachee: /api/coachee/documents/{doc_id}/files/{file_id}/preview
                    import re
                    match = re.search(r'/api/coachee/documents/(\d+)/', content_url)
                    if match:
                        document_id = match.group(1)
                        # Convertir a URL del coach: /api/coach/documents/{doc_id}/view
                        content_url = f"/api/coach/documents/{document_id}/view"
                        logger.info(f"✅ TRANSFORM: Content ID {content.id} - Transformado de {content.content_url} a {content_url}")
                    else:
                        logger.warning(f"⚠️  TRANSFORM: Content ID {content.id} - No se pudo extraer document_id de URL: {content_url}")
                else:
                    logger.info(f"⏭️  TRANSFORM: Content ID {content.id} - No requiere transformación (type={content.content_type}, has_coachee_url={'/api/coachee/documents/' in content_url})")
                
                content_data = {
                    'id': content.id,
                    'title': content.title,
                    'description': content.description,
                    'content_type': content.content_type,
                    'content_url': content_url,
                    'thumbnail_url': content.thumbnail_url,
                    'duration': content.duration,
                    'is_viewed': content.is_viewed,
                    'viewed_at': content.viewed_at.isoformat() if content.viewed_at else None,
                    'assigned_at': content.assigned_at.isoformat() if content.assigned_at else None,
                    'coachee_name': coachee.full_name if coachee else 'Coachee no encontrado',
                    'coachee_email': coachee.email if coachee else 'Email no disponible',
                    'coachee_id': content.coachee_id,
                    'view_mode': 'all'
                }
                content_list.append(content_data)
        
        # Obtener lista de coachees para filtros
        coachees_query = db.session.query(User.id, User.full_name).join(
            Content, User.id == Content.coachee_id
        ).filter(
            Content.coach_id == current_coach.id,
            Content.is_active == True
        ).distinct().order_by(User.full_name)
        
        coachees_list = [{'id': row.id, 'name': row.full_name} for row in coachees_query.all()]
        
        # Calcular estadísticas totales
        total_assigned = len(content_items)
        total_viewed = sum(1 for c in content_items if c.is_viewed)
        total_pending = total_assigned - total_viewed
        
        logger.info(f"📤 RESPONSE: Enviando {len(content_list)} items en content_list")
        logger.info(f"📈 STATS: total_assigned={total_assigned}, total_viewed={total_viewed}, total_pending={total_pending}")
        
        # Log detalles de los primeros items de la respuesta
        for i, item in enumerate(content_list[:3]):
            logger.info(f"📋 RESPONSE-ITEM-{i}: ID={item['id']}, Title='{item['title']}', View_Mode='{item.get('view_mode', 'N/A')}'")
        
        return jsonify({
            'success': True,
            'content': content_list,
            'statistics': {
                'total_assigned': total_assigned,
                'total_viewed': total_viewed,
                'total_pending': total_pending
            },
            'coachees': coachees_list,
            'current_filter': {
                'coachee_id': coachee_filter,
                'view_mode': view_mode
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_get_assigned_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo contenido asignado: {str(e)}'}), 500

@app.route('/api/coach/content/<int:content_id>', methods=['DELETE'])
@coach_session_required
def api_coach_delete_content(content_id):
    """Eliminar contenido asignado (solo el coach que lo asignó)"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden eliminar contenido.'}), 403
        
        # Buscar el contenido y verificar que pertenece a este coach
        content = Content.query.filter_by(
            id=content_id,
            coach_id=current_coach.id,
            is_active=True
        ).first()
        
        if not content:
            return jsonify({'error': 'Contenido no encontrado o no pertenece a este coach'}), 404
        
        # Marcar como inactivo en lugar de eliminar
        content.is_active = False
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Contenido eliminado exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coach_delete_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error eliminando contenido: {str(e)}'}), 500

@app.route('/api/coach/content/<int:content_id>/share', methods=['POST'])
@coach_session_required
def api_coach_share_content(content_id):
    """Compartir contenido existente con múltiples coachees (crear copias)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"📤 SHARE-CONTENT: Coach {current_coach.id if current_coach else 'None'} intenta compartir content_id={content_id}")
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden compartir contenido.'}), 403
        
        # Obtener el contenido original (puede estar asignado a cualquier coachee)
        logger.info(f"🔍 Buscando Content: id={content_id}, coach_id={current_coach.id}, is_active=True")
        original_content = Content.query.filter_by(
            id=content_id,
            coach_id=current_coach.id,
            is_active=True
        ).first()
        
        if not original_content:
            # Debug: Ver si existe con otros filtros
            any_with_id = Content.query.filter_by(id=content_id).first()
            logger.error(f"❌ Contenido {content_id} no encontrado para coach {current_coach.id}")
            logger.error(f"   ¿Existe con ese ID en DB? {any_with_id is not None}")
            if any_with_id:
                logger.error(f"   Pero pertenece a coach_id={any_with_id.coach_id}, is_active={any_with_id.is_active}")
            return jsonify({'error': 'Contenido no encontrado en tu biblioteca'}), 404
        
        logger.info(f"✅ Contenido encontrado: '{original_content.title}' (URL: {original_content.content_url})")
        
        # Obtener lista de coachee_ids y community_ids del request
        data = request.get_json()
        coachee_ids = data.get('coachee_ids', [])
        community_ids = data.get('community_ids', [])
        
        logger.info(f"📋 Coachee IDs recibidos: {coachee_ids}")
        logger.info(f"📋 Community IDs recibidos: {community_ids}")
        
        if (not coachee_ids or not isinstance(coachee_ids, list)) and (not community_ids or not isinstance(community_ids, list)):
            return jsonify({'error': 'Debe proporcionar una lista de coachee_ids y/o community_ids'}), 400
        
        # Validar que todos los coachees pertenecen a este coach
        logger.info(f"🔍 Buscando coachees con: coach_id={current_coach.id}, role='coachee'")
        
        # Quitar el filtro is_active porque está causando problemas
        valid_coachees = User.query.filter(
            User.id.in_(coachee_ids),
            User.coach_id == current_coach.id,
            User.role == 'coachee'
        ).all()
        
        logger.info(f"📊 Coachees encontrados: {len(valid_coachees)} de {len(coachee_ids)} solicitados")
        for coachee in valid_coachees:
            logger.info(f"   ✅ Coachee válido: {coachee.full_name} (ID: {coachee.id})")
        
        if len(valid_coachees) != len(coachee_ids):
            # Debug: Ver qué coachees no se encontraron
            found_ids = {c.id for c in valid_coachees}
            missing_ids = set(coachee_ids) - found_ids
            logger.error(f"❌ Coachees no encontrados o inválidos: {missing_ids}")
            
            # Ver detalles de los coachees no válidos
            for missing_id in missing_ids:
                user = User.query.get(missing_id)
                if user:
                    logger.error(f"   ⚠️ User ID {missing_id}: coach_id={user.coach_id}, role={user.role}, is_active={user.is_active}")
                else:
                    logger.error(f"   ⚠️ User ID {missing_id}: No existe en la base de datos")
            
            return jsonify({'error': 'Algunos coachees no son válidos o no te pertenecen'}), 400
        
        # Crear copias del contenido para cada coachee
        shared_count = 0
        for coachee in valid_coachees:
            # Verificar si ya existe este contenido para este coachee
            existing = Content.query.filter_by(
                coach_id=current_coach.id,
                coachee_id=coachee.id,
                content_url=original_content.content_url,
                is_active=True
            ).first()
            
            if existing:
                logger.info(f"⚠️  Contenido ya existe para coachee {coachee.id}, saltando...")
                continue
            
            # Crear nueva instancia del contenido
            new_content = Content(
                coach_id=current_coach.id,
                coachee_id=coachee.id,
                title=original_content.title,
                description=original_content.description,
                content_type=original_content.content_type,
                content_url=original_content.content_url,
                thumbnail_url=original_content.thumbnail_url,
                duration=original_content.duration,
                is_active=True,
                is_viewed=False,
                assigned_at=datetime.utcnow()
            )
            db.session.add(new_content)
            shared_count += 1
            logger.info(f"✅ Contenido compartido con coachee {coachee.full_name} (ID: {coachee.id})")
        
        db.session.commit()
        
        # Compartir con comunidades - DESHABILITADO: columnas community no existen en producción
        community_shared_count = 0
        # if community_ids:
        #     logger.info(f"🔄 Compartiendo con {len(community_ids)} comunidad(es)...")
        #     
        #     for community_id in community_ids:
        #         # Verificar que la comunidad existe y el coach es miembro
        #         membership = CommunityMembership.query.filter_by(
        #             community_id=community_id,
        #             coach_id=current_coach.id,
        #             is_active=True
        #         ).first()
        #         
        #         if not membership:
        #             logger.warning(f"⚠️ Coach no es miembro de la comunidad {community_id}, saltando...")
        #             continue
        #         
        #         # Verificar si ya existe este contenido compartido en esta comunidad
        #         existing_community_content = Content.query.filter_by(
        #             coach_id=current_coach.id,
        #             community_id=community_id,
        #             content_url=original_content.content_url,
        #             is_active=True,
        #             shared_with_community=True
        #         ).first()
        #         
        #         if existing_community_content:
        #             logger.info(f"⚠️ Contenido ya existe en comunidad {community_id}, saltando...")
        #             continue
        #         
        #         # Crear nueva instancia del contenido para la comunidad
        #         community_content = Content(
        #             coach_id=current_coach.id,
        #             community_id=community_id,
        #             coachee_id=None,  # No asignado a coachee específico
        #             title=original_content.title,
        #             description=original_content.description,
        #             content_type=original_content.content_type,
        #             content_url=original_content.content_url,
        #             thumbnail_url=original_content.thumbnail_url,
        #             duration=original_content.duration,
        #             is_active=True,
        #             is_viewed=False,
        #             shared_with_community=True,
        #             shared_at=datetime.utcnow()
        #         )
        #         db.session.add(community_content)
        #         community_shared_count += 1
        #         logger.info(f"✅ Contenido compartido con comunidad {community_id}")
        #     
        #     db.session.commit()
        
        # Preparar mensaje de respuesta
        total_shared = shared_count + community_shared_count
        
        if total_shared == 0:
            return jsonify({
                'success': True,
                'message': 'El contenido ya estaba compartido con todos los destinatarios seleccionados',
                'shared_count': 0,
                'coachees_count': 0,
                'communities_count': 0
            }), 200
        
        message_parts = []
        if shared_count > 0:
            message_parts.append(f'{shared_count} coachee(s)')
        if community_shared_count > 0:
            message_parts.append(f'{community_shared_count} comunidad(es)')
        
        message = f'Contenido compartido exitosamente con {" y ".join(message_parts)}'
        
        return jsonify({
            'success': True,
            'message': message,
            'shared_count': total_shared,
            'coachees_count': shared_count,
            'communities_count': community_shared_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coach_share_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error compartiendo contenido: {str(e)}'}), 500

@app.route('/api/coach/content/upload', methods=['POST'])
@coach_session_required
def api_coach_upload_content():
    """Subir nuevo contenido a la biblioteca del coach (sin asignar a coachee específico)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden subir contenido.'}), 403
        
        # Obtener datos del formulario
        title = request.form.get('title')
        description = request.form.get('description', '')
        content_type = request.form.get('content_type', 'video')  # video, document, article
        content_url = request.form.get('url', '')
        
        # NUEVO: Soporte para compartir en comunidad
        community_id = request.form.get('community_id')
        shared_with_community = request.form.get('shared_with_community', 'false').lower() == 'true'
        
        # Validar campos requeridos
        if not title:
            return jsonify({'error': 'El título es requerido'}), 400
        
        if not content_type:
            return jsonify({'error': 'El tipo de contenido es requerido'}), 400
        
        # Si se especifica compartir en comunidad, validar membresía
        if community_id and shared_with_community:
            try:
                community_id = int(community_id)
                membership = CommunityMembership.query.filter_by(
                    community_id=community_id,
                    coach_id=current_coach.id,
                    is_active=True
                ).first()
                
                if not membership:
                    return jsonify({'error': 'No eres miembro de esta comunidad'}), 403
            except (ValueError, TypeError):
                return jsonify({'error': 'ID de comunidad inválido'}), 400
        else:
            community_id = None
            shared_with_community = False
        
        # Manejar archivo subido (para documentos)
        file = request.files.get('file')
        if file and file.filename:
            # Aquí puedes implementar guardado de archivo
            # Por ahora, solo lo registramos como URL placeholder
            filename = file.filename
            # TODO: Guardar archivo en servidor o S3
            if not content_url:
                content_url = f'file://{filename}'  # Placeholder para archivo local
            logger.info(f"📁 Archivo recibido: {filename}")
        
        # Validar que haya URL o archivo
        if not content_url:
            return jsonify({'error': 'Se requiere una URL o un archivo'}), 400
        
        # Generar thumbnail para videos de YouTube
        thumbnail_url = None
        if content_type == 'video' and 'youtube.com' in content_url or 'youtu.be' in content_url:
            import re
            youtube_match = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/)([^&\s]+)', content_url)
            if youtube_match:
                video_id = youtube_match.group(1)
                thumbnail_url = f'https://img.youtube.com/vi/{video_id}/maxresdefault.jpg'
        
        # Crear contenido SIN asignar a coachee (coachee_id = None para biblioteca)
        # MODIFICADO: Agregar campos de comunidad
        content = Content(
            coach_id=current_coach.id,
            coachee_id=None,  # NULL = contenido de biblioteca (no asignado aún)
            title=title,
            description=description,
            content_type=content_type,
            content_url=content_url,
            thumbnail_url=thumbnail_url,
            is_active=True,
            community_id=community_id if shared_with_community else None,
            shared_with_community=shared_with_community,
            shared_at=datetime.utcnow() if shared_with_community else None
        )
        
        db.session.add(content)
        db.session.commit()
        
        community_msg = f" y compartido en comunidad {community_id}" if shared_with_community else ""
        logger.info(f"✅ Contenido creado: ID={content.id}, Coach={current_coach.id}, Type={content_type}, Title={title}{community_msg}")
        
        return jsonify({
            'success': True,
            'message': 'Contenido subido exitosamente',
            'id': content.id,
            'title': content.title,
            'content_type': content.content_type,
            'content_url': content.content_url,
            'thumbnail_url': content.thumbnail_url,
            'community_id': content.community_id,
            'shared_with_community': content.shared_with_community,
            'created_at': content.assigned_at.strftime('%Y-%m-%d %H:%M:%S')
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coach_upload_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error subiendo contenido: {str(e)}'}), 500

# ⚠️ FUNCIÓN DUPLICADA COMENTADA - Ver línea 11317 para la función correcta
"""
@app.route('/api/coach/content/<int:content_id>/share', methods=['POST'])
@coach_session_required
def api_coach_share_content(content_id):
    # Compartir contenido de biblioteca con uno o varios coachees
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que el contenido existe y pertenece al coach
        library_content = Content.query.filter_by(
            id=content_id,
            coach_id=current_coach.id,
            coachee_id=None,  # Contenido de biblioteca
            is_active=True
        ).first()
        
        if not library_content:
            return jsonify({'error': 'Contenido no encontrado en tu biblioteca'}), 404
        
        data = request.get_json()
        coachee_ids = data.get('coachee_ids', [])
        
        if not coachee_ids:
            return jsonify({'error': 'Debes seleccionar al menos un coachee'}), 400
        
        # Verificar que los coachees pertenecen al coach
        coachees = User.query.filter(
            User.id.in_(coachee_ids),
            User.coach_id == current_coach.id,
            User.role == 'coachee'
        ).all()
        
        if len(coachees) != len(coachee_ids):
            return jsonify({'error': 'Algunos coachees no son válidos'}), 400
        
        # Crear copias del contenido para cada coachee
        shared_count = 0
        for coachee in coachees:
            # Verificar si ya existe
            existing = Content.query.filter_by(
                coach_id=current_coach.id,
                coachee_id=coachee.id,
                title=library_content.title,
                content_url=library_content.content_url,
                is_active=True
            ).first()
            
            if not existing:
                shared_content = Content(
                    coach_id=current_coach.id,
                    coachee_id=coachee.id,
                    title=library_content.title,
                    description=library_content.description,
                    content_type=library_content.content_type,
                    content_url=library_content.content_url,
                    thumbnail_url=library_content.thumbnail_url,
                    duration=library_content.duration,
                    is_active=True
                )
                db.session.add(shared_content)
                shared_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Contenido compartido con {shared_count} coachee(s)',
            'shared_count': shared_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en api_coach_share_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error compartiendo contenido: {str(e)}'}), 500
"""

@app.route('/api/coach/content/library', methods=['GET'])
@coach_session_required
def api_coach_get_library():
    """Obtener contenido de biblioteca del coach (no asignado)"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Obtener solo contenido de biblioteca (coachee_id = NULL)
        library_items = Content.query.filter_by(
            coach_id=current_coach.id,
            coachee_id=None,
            is_active=True
        ).order_by(Content.assigned_at.desc()).all()
        
        content_list = []
        for item in library_items:
            content_list.append({
                'id': item.id,
                'title': item.title,
                'description': item.description,
                'content_type': item.content_type,
                'content_url': item.content_url,
                'thumbnail_url': item.thumbnail_url,
                'created_at': item.assigned_at.strftime('%d/%m/%Y')
            })
        
        return jsonify({
            'success': True,
            'content': content_list,
            'total': len(content_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_get_library: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo biblioteca: {str(e)}'}), 500

@app.route('/api/coach/my-content', methods=['GET'])
@coach_session_required
def api_coach_get_my_content():
    """Obtener todo el contenido publicado por el coach (vista simplificada para feed)"""
    try:
        # Usar g.current_user que es establecido por @coach_session_required
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"🔍 MY-CONTENT: Request recibida. Current coach: {current_coach}")
        logger.info(f"🔍 MY-CONTENT: Coach ID: {current_coach.id if current_coach else 'None'}, Role: {current_coach.role if current_coach else 'None'}")
        
        if not current_coach or current_coach.role != 'coach':
            logger.error(f"❌ MY-CONTENT: Acceso denegado. current_coach: {current_coach}, role: {current_coach.role if current_coach else 'None'}")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden ver su contenido.'}), 403
        
        # Obtener todo el contenido del coach agrupado por título/URL
        content_items = Content.query.filter_by(
            coach_id=current_coach.id,
            is_active=True
        ).order_by(Content.assigned_at.desc()).all()
        
        logger.info(f"🔍 MY-CONTENT: Coach {current_coach.id} solicitando su contenido publicado")
        logger.info(f"📊 MY-CONTENT: Encontrados {len(content_items)} items totales")
        
        # Agrupar contenido único por título y URL
        unique_content = {}
        for content in content_items:
            key = f"{content.title}_{content.content_url}"
            if key not in unique_content:
                # Transformar URL de documento para que funcione en el feed del coach
                content_url = content.content_url
                if content.content_type == 'document' and '/api/coachee/documents/' in content_url:
                    # Extraer document_id de la URL del coachee: /api/coachee/documents/{doc_id}/files/{file_id}/preview
                    import re
                    match = re.search(r'/api/coachee/documents/(\d+)/', content_url)
                    if match:
                        document_id = match.group(1)
                        # Convertir a URL del coach: /api/coach/documents/{doc_id}/view
                        content_url = f"/api/coach/documents/{document_id}/view"
                        logger.info(f"📄 MY-CONTENT: Transformando URL de documento de {content.content_url} a {content_url}")
                
                unique_content[key] = {
                    'id': content.id,
                    'title': content.title,
                    'description': content.description,
                    'content_type': content.content_type,
                    'content_url': content_url,
                    'thumbnail_url': content.thumbnail_url,
                    'created_at': content.assigned_at.isoformat() if content.assigned_at else None,
                    'assigned_count': 0
                }
            unique_content[key]['assigned_count'] += 1
        
        # Convertir a lista
        content_list = list(unique_content.values())
        
        logger.info(f"✅ MY-CONTENT: Devolviendo {len(content_list)} items únicos de contenido")
        logger.info(f"📦 MY-CONTENT: Contenido a enviar: {content_list}")
        
        return jsonify({
            'success': True,
            'content': content_list
        }), 200
        
    except Exception as e:
        logger.error(f"❌ MY-CONTENT: Error en api_coach_get_my_content: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo contenido: {str(e)}'}), 500

@app.route('/api/coach/unified-feed', methods=['GET'])
@coach_session_required
def api_coach_get_unified_feed():
    """
    Obtener feed unificado: contenido propio + contenido compartido en comunidades.
    Retorna contenido mezclado ordenado cronológicamente con indicador de fuente.
    """
    try:
        current_coach = getattr(g, 'current_user', None)
        
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado. Solo coaches.'}), 403
        
        # 1. Obtener contenido propio del coach
        own_content = Content.query.filter_by(
            coach_id=current_coach.id,
            is_active=True
        ).all()
        
        # 2. Obtener comunidades donde es miembro activo - DESHABILITADO: columnas community no existen
        # my_memberships = CommunityMembership.query.filter_by(
        #     coach_id=current_coach.id,
        #     is_active=True
        # ).all()
        # 
        # community_ids = [m.community_id for m in my_memberships]
        
        # 3. Obtener contenido compartido en esas comunidades - DESHABILITADO
        community_content = []
        # if community_ids:
        #     community_content = Content.query.filter(
        #         Content.community_id.in_(community_ids),
        #         Content.shared_with_community == True,
        #         Content.is_active == True,
        #         Content.coach_id != current_coach.id  # Excluir contenido propio
        #     ).all()
        
        # 4. Combinar y formatear todo el contenido
        unified_feed = []
        
        # Procesar contenido propio
        for content in own_content:
            # Transformar URL de documento si es necesario
            content_url = content.content_url
            if content.content_type == 'document' and '/api/coachee/documents/' in content_url:
                import re
                match = re.search(r'/api/coachee/documents/(\d+)/', content_url)
                if match:
                    document_id = match.group(1)
                    content_url = f"/api/coach/documents/{document_id}/view"
            
            # community_info = None  # DESHABILITADO: columnas community no existen
            # if content.shared_with_community and content.community_id:
            #     community = CoachCommunity.query.get(content.community_id)
            #     if community:
            #         community_info = {
            #             'id': community.id,
            #             'name': community.name
            #         }
            
            unified_feed.append({
                'id': content.id,
                'title': content.title,
                'description': content.description,
                'content_type': content.content_type,
                'content_url': content_url,
                'thumbnail_url': content.thumbnail_url,
                'created_at': content.assigned_at.isoformat() if content.assigned_at else None,  # Solo assigned_at
                'source_type': 'own',  # Contenido propio
                'author_name': current_coach.full_name,
                'author_id': current_coach.id,
                'author_avatar': current_coach.avatar_url,
                'community': None  # Sin comunidades por ahora
            })
        
        # Procesar contenido de comunidades
        for content in community_content:
            community = CoachCommunity.query.get(content.community_id)
            author = content.coach
            
            # Transformar URL de documento si es necesario
            content_url = content.content_url
            if content.content_type == 'document' and '/api/coachee/documents/' in content_url:
                import re
                match = re.search(r'/api/coachee/documents/(\d+)/', content_url)
                if match:
                    document_id = match.group(1)
                    content_url = f"/api/coach/documents/{document_id}/view"
            
            unified_feed.append({
                'id': content.id,
                'title': content.title,
                'description': content.description,
                'content_type': content.content_type,
                'content_url': content_url,
                'thumbnail_url': content.thumbnail_url,
                'created_at': (content.shared_at or content.assigned_at).isoformat() if (content.shared_at or content.assigned_at) else None,
                'source_type': 'community',  # Contenido de comunidad
                'author_name': author.full_name if author else 'Desconocido',
                'author_id': author.id if author else None,
                'author_avatar': author.avatar_url if author else None,
                'community': {
                    'id': community.id,
                    'name': community.name
                } if community else None
            })
        
        # 5. Ordenar por fecha descendente (más reciente primero)
        unified_feed.sort(
            key=lambda x: datetime.fromisoformat(x['created_at']) if x['created_at'] else datetime.min,
            reverse=True
        )
        
        logger.info(f"✅ UNIFIED-FEED: Coach {current_coach.id} - {len(own_content)} propios + {len(community_content)} de comunidades = {len(unified_feed)} total")
        
        return jsonify({
            'success': True,
            'content': unified_feed,
            'stats': {
                'own': len(own_content),
                'community': len(community_content),
                'total': len(unified_feed)
            }
        }), 200
        
    except Exception as e:
        logger.error(f"❌ UNIFIED-FEED: Error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo feed unificado'}), 500

@app.route('/api/coach/update-coachee/<int:coachee_id>', methods=['PUT'])
@coach_session_required
def api_coach_update_coachee(coachee_id):
    """Actualizar información de un coachee"""
    try:
        current_coach = getattr(g, 'current_user', None)
        
        logger.info(f"✏️ UPDATE_COACHEE: Request from coach {current_coach.username if current_coach else 'Unknown'} for coachee {coachee_id}")
        
        # Verificar que es un coach
        if not current_coach or current_coach.role != 'coach':
            logger.warning(f"❌ UPDATE_COACHEE: Access denied for user {current_coach.username if current_coach else 'None'}")
            return jsonify({'error': 'Acceso denegado. Solo coaches pueden actualizar coachees.'}), 403
        
        # Buscar el coachee y verificar que pertenece al coach actual
        coachee = User.query.filter_by(
            id=coachee_id, 
            coach_id=current_coach.id, 
            role='coachee'
        ).first()
        
        if not coachee:
            logger.warning(f"❌ UPDATE_COACHEE: Coachee {coachee_id} not found or doesn't belong to coach {current_coach.id}")
            return jsonify({'error': 'Coachee no encontrado o no pertenece a este coach'}), 404
        
        data = request.get_json()
        logger.info(f"📝 UPDATE_COACHEE: Received data: {data}")
        
        # Campos que se pueden actualizar
        full_name = data.get('full_name')
        email = data.get('email')
        new_password = data.get('password')
        
        # Validaciones
        if full_name is not None:
            if not full_name.strip():
                return jsonify({'error': 'El nombre no puede estar vacío'}), 400
            coachee.full_name = full_name.strip()
        
        if email is not None:
            if not email.strip():
                return jsonify({'error': 'El email no puede estar vacío'}), 400
            if '@' not in email:
                return jsonify({'error': 'Formato de email inválido'}), 400
            
            # Verificar que el email no esté en uso por otro usuario
            existing_email = User.query.filter(
                User.email == email,
                User.id != coachee_id
            ).first()
        if new_password is not None:
            if len(new_password) < 4:
                return jsonify({'error': 'La contraseña debe tener al menos 4 caracteres'}), 400
            coachee.set_password(new_password)
            coachee.original_password = new_password  # Actualizar también la contraseña original visible
            db.session.add(coachee)  # Asegurar que SQLAlchemy detecte el cambio
            db.session.flush()  # Forzar escritura inmediata a BD
        
        # Guardar cambios
        db.session.commit()    # Confirmar cambios
        db.session.expire_all()  # Expirar caché DESPUÉS del commit
        
        logger.info(f"✅ UPDATE_COACHEE: Coachee {coachee_id} updated successfully")
        
        return jsonify({
            'success': True,
            'message': 'Coachee actualizado exitosamente',
            'coachee': {
                'id': coachee.id,
                'full_name': coachee.full_name,
                'email': coachee.email,
                'password': coachee.original_password  # Para que se actualice en la tabla
            }
        })
        
    except Exception as e:
        logger.error(f"Error en api_coach_update_coachee: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error actualizando coachee: {str(e)}'}), 500

@app.route('/api/coach/coachee-notes/<int:coachee_id>', methods=['GET', 'POST'])
@coach_session_required
def api_coach_coachee_notes(coachee_id):
    """Gestionar notas del coach sobre un coachee"""
    try:
        current_coach = g.current_user
        
        # Verificar que el coachee pertenece al coach
        coachee = User.query.filter_by(
            id=coachee_id,
            coach_id=current_coach.id,
            role='coachee'
        ).first()
        
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no pertenece a este coach'}), 404
        
        if request.method == 'GET':
            # Retornar notas existentes
            import json
            notes = []
            if coachee.coach_notes:
                try:
                    notes = json.loads(coachee.coach_notes)
                except:
                    notes = []
            
            return jsonify({
                'success': True,
                'notes': notes,
                'coachee_name': coachee.full_name
            })
        
        elif request.method == 'POST':
            # Guardar nueva nota o actualizar todas
            import json
            data = request.get_json()
            notes = data.get('notes', [])
            
            # Validar formato de notas
            if not isinstance(notes, list):
                return jsonify({'error': 'Formato de notas inválido'}), 400
            
            # Guardar como JSON
            coachee.coach_notes = json.dumps(notes, ensure_ascii=False)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Notas guardadas exitosamente',
                'notes': notes
            })
    
    except Exception as e:
        logger.error(f"Error en api_coach_coachee_notes: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error gestionando notas: {str(e)}'}), 500

# ================================
# COACH CALENDAR APIs
# ================================

@app.route('/api/coach/availability', methods=['GET', 'POST'])
@coach_session_required
def api_coach_availability():
    """Gestionar disponibilidad del coach"""
    try:
        current_coach = g.current_user
        
        if request.method == 'GET':
            # Obtener disponibilidad actual
            availability = CoachAvailability.query.filter_by(
                coach_id=current_coach.id,
                is_active=True
            ).order_by(CoachAvailability.day_of_week, CoachAvailability.start_time).all()
            
            if not availability:
                return jsonify({
                    'success': True,
                    'availability': []
                }), 200
            
            # Agrupar por horario (start_time, end_time)
            # Asumimos que todos tienen el mismo horario y agrupamos los días
            time_groups = {}
            for slot in availability:
                time_key = f"{slot.start_time.strftime('%H:%M')}-{slot.end_time.strftime('%H:%M')}"
                if time_key not in time_groups:
                    time_groups[time_key] = {
                        'start_time': slot.start_time.strftime('%H:%M'),
                        'end_time': slot.end_time.strftime('%H:%M'),
                        'days': []
                    }
                time_groups[time_key]['days'].append(slot.day_of_week)
            
            # Convertir a formato esperado por el frontend
            availability_data = []
            for time_key, group_data in time_groups.items():
                availability_data.append({
                    'available_days': json.dumps(sorted(group_data['days'])),  # JSON string con días ordenados
                    'start_time': group_data['start_time'],
                    'end_time': group_data['end_time'],
                    'is_active': True
                })
            
            return jsonify({
                'success': True,
                'availability': availability_data
            }), 200
        
        elif request.method == 'POST':
            data = request.get_json()

            # Soportar formato múltiple: { slots: [...] } o legacy { available_days, start_time, end_time }
            slots = data.get('slots')
            if not slots:
                # Legacy: convertir formato antiguo a slots
                available_days_str = data.get('available_days', '[]')
                start_time_str = data.get('start_time')
                end_time_str = data.get('end_time')
                if not start_time_str or not end_time_str:
                    return jsonify({'error': 'Horarios de inicio y fin son requeridos'}), 400
                try:
                    available_days = json.loads(available_days_str) if isinstance(available_days_str, str) else available_days_str
                except:
                    available_days = []
                if not available_days:
                    return jsonify({'error': 'Debes seleccionar al menos un día'}), 400
                slots = [{'days': available_days, 'start_time': start_time_str, 'end_time': end_time_str}]

            # Validar que haya al menos un slot
            if not slots or len(slots) == 0:
                return jsonify({'error': 'Debes configurar al menos una franja horaria'}), 400

            # Eliminar disponibilidad existente
            CoachAvailability.query.filter_by(coach_id=current_coach.id).delete()

            total_created = 0
            for slot in slots:
                days = slot.get('days', [])
                st = slot.get('start_time')
                et = slot.get('end_time')
                if not days or not st or not et:
                    continue
                start_time = datetime.strptime(st, '%H:%M').time()
                end_time = datetime.strptime(et, '%H:%M').time()
                if end_time <= start_time:
                    continue
                for day in days:
                    new_slot = CoachAvailability(
                        coach_id=current_coach.id,
                        day_of_week=int(day),
                        start_time=start_time,
                        end_time=end_time,
                        is_active=True
                    )
                    db.session.add(new_slot)
                    total_created += 1

            if total_created == 0:
                return jsonify({'error': 'No se crearon franjas válidas. Revisa los datos.'}), 400

            db.session.commit()

            logger.info(f"✅ Disponibilidad guardada para coach {current_coach.id}: {total_created} slots desde {len(slots)} franjas")
            
            return jsonify({
                'success': True,
                'message': 'Disponibilidad actualizada correctamente'
            }), 200
            
    except Exception as e:
        logger.error(f"Error en api_coach_availability: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error gestionando disponibilidad: {str(e)}'}), 500

@app.route('/api/coach/sessions', methods=['GET'])
@coach_session_required
def api_coach_sessions():
    """Obtener todas las sesiones del coach (SOLO confirmadas, NO pending)"""
    try:
        current_coach = g.current_user
        
        # Parámetros de filtrado
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # IMPORTANTE: Excluir sesiones 'pending' y 'cancelled'
        # Pending van a Solicitudes, cancelled no se muestran en calendario
        # Solo mostrar: confirmed (incluye self_activity), completed, proposed
        query = CoachingSession.query.filter_by(coach_id=current_coach.id).filter(
            CoachingSession.status.in_(['confirmed', 'completed', 'proposed'])
        )
        
        if start_date:
            # Extraer solo la fecha del formato ISO de FullCalendar (2025-09-28T00:00:00-03:00)
            date_part = start_date.split('T')[0] if 'T' in start_date else start_date
            query = query.filter(CoachingSession.session_date >= datetime.strptime(date_part, '%Y-%m-%d').date())
        if end_date:
            # Extraer solo la fecha del formato ISO de FullCalendar
            date_part = end_date.split('T')[0] if 'T' in end_date else end_date
            query = query.filter(CoachingSession.session_date <= datetime.strptime(date_part, '%Y-%m-%d').date())
        
        sessions = query.order_by(CoachingSession.session_date, CoachingSession.start_time).all()
        
        logger.info(f"📅 CALENDARIO: Coach {current_coach.id} - {len(sessions)} sesiones (excluye pending y cancelled)")
        
        sessions_data = []
        for session in sessions:
            sessions_data.append({
                'id': session.id,
                'coachee_id': session.coachee_id,
                'coachee_name': session.coachee_name if session.coachee_id else 'Tiempo Personal',
                'session_date': session.session_date.isoformat(),
                'start_time': session.start_time.strftime('%H:%M'),
                'end_time': session.end_time.strftime('%H:%M'),
                'status': session.status,
                'session_type': session.session_type,
                'activity_type': session.activity_type,
                'activity_title': session.activity_title,
                'title': session.title or session.activity_title or f'Sesión con {session.coachee_name if session.coachee_id else "Tiempo Personal"}',
                'description': session.description or session.activity_description,
                'location': session.location,
                'start': session.session_datetime.isoformat(),
                'end': session.session_end_datetime.isoformat(),
                'created_at': session.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'sessions': sessions_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_sessions: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo sesiones: {str(e)}'}), 500

@app.route('/api/coach/session-requests-old', methods=['GET', 'PUT'])
@coach_session_required
def api_coach_session_requests_old():
    """Gestionar solicitudes de sesión pendientes (LEGACY - usando CoachingSession)"""
    try:
        current_coach = g.current_user
        
        if request.method == 'GET':
            # Obtener solicitudes pendientes
            requests = CoachingSession.query.filter_by(
                coach_id=current_coach.id,
                status='pending'
            ).order_by(CoachingSession.created_at.desc()).all()
            
            logger.info(f"📋 SOLICITUDES: Coach {current_coach.id} tiene {len(requests)} solicitudes pendientes")
            
            requests_data = []
            for req in requests:
                # Obtener el nombre del coachee de forma segura
                coachee_name = 'Sin nombre'
                if req.coachee_id:
                    coachee = User.query.get(req.coachee_id)
                    if coachee:
                        coachee_name = coachee.full_name
                
                request_item = {
                    'id': req.id,
                    'coachee_id': req.coachee_id,
                    'coachee_name': coachee_name,
                    'session_date': req.session_date.isoformat(),
                    'preferred_date': req.session_date.isoformat(),  # Alias para frontend
                    'start_time': req.start_time.strftime('%H:%M'),
                    'end_time': req.end_time.strftime('%H:%M'),
                    'title': req.title or 'Sesión de Coaching',
                    'description': req.description or '',
                    'location': req.location or 'Por definir',
                    'created_at': req.created_at.isoformat()
                }
                requests_data.append(request_item)
                logger.info(f"  📌 Solicitud {req.id}: {coachee_name} - {req.session_date} {req.start_time}")
            
            return jsonify({
                'success': True,
                'requests': requests_data
            }), 200
        
        elif request.method == 'PUT':
            # Responder a una solicitud
            data = request.get_json()
            session_id = data.get('session_id')
            action = data.get('action')  # 'confirm', 'reject', 'propose'
            
            logger.info(f"🔄 REAGENDAR: Coach {current_coach.id} intenta {action} en sesión {session_id}")
            
            # Para 'propose', permitir reagendar sesiones con estatus pending, confirmed, o proposed
            if action == 'propose':
                allowed_statuses = ['pending', 'confirmed', 'proposed']
                session = CoachingSession.query.filter(
                    CoachingSession.id == session_id,
                    CoachingSession.coach_id == current_coach.id,
                    CoachingSession.status.in_(allowed_statuses)
                ).first()
                
                if session:
                    logger.info(f"✅ REAGENDAR: Sesión encontrada - ID: {session.id}, Estado: {session.status}")
                else:
                    # Verificar si la sesión existe pero con otro estatus
                    any_session = CoachingSession.query.filter_by(
                        id=session_id,
                        coach_id=current_coach.id
                    ).first()
                    if any_session:
                        logger.warning(f"❌ REAGENDAR: Sesión {session_id} existe pero con estatus no permitido: {any_session.status}")
                    else:
                        logger.warning(f"❌ REAGENDAR: Sesión {session_id} no encontrada para coach {current_coach.id}")
            else:
                # Para otras acciones, solo sesiones pendientes
                session = CoachingSession.query.filter_by(
                    id=session_id,
                    coach_id=current_coach.id,
                    status='pending'
                ).first()
            
            if not session:
                if action == 'propose':
                    return jsonify({'error': 'Sesión no encontrada o no se puede reagendar (cancelada/completada)'}), 404
                else:
                    return jsonify({'error': 'Solicitud no encontrada'}), 404
            
            if action == 'confirm':
                session.status = 'confirmed'
                message = f'Sesión confirmada para {session.session_date} a las {session.start_time}'
            
            elif action == 'reject':
                session.status = 'cancelled'
                message = 'Solicitud rechazada'
            
            elif action == 'propose':
                # Proponer nuevo horario
                proposed_date = data.get('proposed_date')
                proposed_start_time = data.get('proposed_start_time')
                proposed_end_time = data.get('proposed_end_time')
                proposal_message = data.get('message', '')
                
                # Crear nueva propuesta
                new_proposal = CoachingSession(
                    coach_id=current_coach.id,
                    coachee_id=session.coachee_id,
                    session_date=datetime.strptime(proposed_date, '%Y-%m-%d').date(),
                    start_time=datetime.strptime(proposed_start_time, '%H:%M').time(),
                    end_time=datetime.strptime(proposed_end_time, '%H:%M').time(),
                    status='proposed',
                    title=session.title,
                    description=session.description,
                    location=session.location,
                    original_session_id=session.id,
                    proposed_by='coach',
                    proposal_message=proposal_message
                )
                
                db.session.add(new_proposal)
                session.status = 'proposal_sent'
                message = f'Propuesta de nuevo horario enviada: {proposed_date} a las {proposed_start_time}'
                
                logger.info(f"✅ PROPUESTA CREADA: Nueva sesión ID será generado, original {session.id} marcada como 'proposal_sent'")
                logger.info(f"📅 PROPUESTA: {proposed_date} de {proposed_start_time} a {proposed_end_time}")
            
            else:
                return jsonify({'error': 'Acción no válida'}), 400
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': message
            }), 200
            
    except Exception as e:
        logger.error(f"Error en api_coach_session_requests: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error gestionando solicitudes: {str(e)}'}), 500

@app.route('/api/coach/session-requests-legacy/<int:request_id>/accept', methods=['POST'])
@coach_session_required
def api_coach_accept_session_request_legacy(request_id):
    """Aceptar una solicitud de sesión (LEGACY - CoachingSession)"""
    try:
        current_coach = g.current_user
        
        # Buscar la solicitud pendiente
        session = CoachingSession.query.filter_by(
            id=request_id,
            coach_id=current_coach.id,
            status='pending'
        ).first()
        
        if not session:
            logger.warning(f"❌ ACEPTAR: Solicitud {request_id} no encontrada o no está pendiente")
            return jsonify({'error': 'Solicitud no encontrada'}), 404
        
        # Cambiar status a confirmed
        session.status = 'confirmed'
        db.session.commit()
        
        logger.info(f"✅ ACEPTADA: Solicitud {request_id} confirmada para {session.session_date} {session.start_time}")
        
        return jsonify({
            'success': True,
            'message': f'Sesión confirmada para {session.session_date.strftime("%d/%m/%Y")} a las {session.start_time.strftime("%H:%M")}'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_accept_session_request: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error aceptando solicitud: {str(e)}'}), 500

@app.route('/api/coach/session-requests-legacy/<int:request_id>/reject', methods=['POST'])
@coach_session_required
def api_coach_reject_session_request_legacy(request_id):
    """Rechazar una solicitud de sesión (LEGACY - CoachingSession)"""
    try:
        current_coach = g.current_user
        data = request.get_json() or {}
        reason = data.get('reason', 'Sin motivo especificado')
        
        # Buscar la solicitud pendiente
        session = CoachingSession.query.filter_by(
            id=request_id,
            coach_id=current_coach.id,
            status='pending'
        ).first()
        
        if not session:
            logger.warning(f"❌ RECHAZAR: Solicitud {request_id} no encontrada o no está pendiente")
            return jsonify({'error': 'Solicitud no encontrada'}), 404
        
        # Cambiar status a cancelled y guardar el motivo
        session.status = 'cancelled'
        session.notes = f"Rechazada por coach: {reason}"
        db.session.commit()
        
        logger.info(f"❌ RECHAZADA: Solicitud {request_id} rechazada. Motivo: {reason}")
        
        return jsonify({
            'success': True,
            'message': 'Solicitud rechazada correctamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_reject_session_request: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error rechazando solicitud: {str(e)}'}), 500

@app.route('/api/coach/block-time', methods=['POST'])
@coach_session_required
def api_coach_block_time():
    """Bloquear tiempo personal en el calendario del coach"""
    try:
        current_coach = g.current_user
        data = request.get_json() or {}
        
        # Validar datos requeridos
        activity_title = data.get('activity_title')
        activity_type = data.get('activity_type')
        session_date_str = data.get('session_date')
        start_time_str = data.get('start_time')
        end_time_str = data.get('end_time')
        description = data.get('description', '')
        
        if not all([activity_title, activity_type, session_date_str, start_time_str, end_time_str]):
            return jsonify({'error': 'Faltan datos requeridos'}), 400
        
        # Parsear fecha y horas
        from datetime import datetime as dt
        session_date = dt.strptime(session_date_str, '%Y-%m-%d').date()
        start_time = dt.strptime(start_time_str, '%H:%M').time()
        end_time = dt.strptime(end_time_str, '%H:%M').time()
        
        # Validar que la fecha no sea en el pasado
        santiago_today = get_santiago_today()
        if session_date < santiago_today:
            return jsonify({'error': 'No se puede bloquear tiempo en fechas pasadas'}), 400
        
        # Validar que la hora de fin sea posterior a la de inicio
        if end_time <= start_time:
            return jsonify({'error': 'La hora de fin debe ser posterior a la hora de inicio'}), 400
        
        # Verificar que no haya conflictos de horario (solo sesiones confirmadas o propuestas)
        conflicts = CoachingSession.query.filter_by(
            coach_id=current_coach.id,
            session_date=session_date
        ).filter(
            CoachingSession.status.in_(['confirmed', 'proposed']),
            db.or_(
                db.and_(
                    CoachingSession.start_time < end_time,
                    CoachingSession.end_time > start_time
                )
            )
        ).all()

        if conflicts:
            return jsonify({'error': 'Ya tienes una sesión o bloqueo en ese horario'}), 400

        # Crear el bloqueo de tiempo
        block = CoachingSession(
            coach_id=current_coach.id,
            coachee_id=None,  # Sin coachee, es actividad personal
            session_date=session_date,
            start_time=start_time,
            end_time=end_time,
            status='confirmed',  # Los bloqueos personales se confirman automáticamente
            session_type='self_activity',
            activity_type=activity_type,
            activity_title=activity_title,
            activity_description=description,
            created_by_coach=True
        )
        
        db.session.add(block)
        db.session.commit()
        
        logger.info(f"✅ BLOQUEO PERSONAL: Coach {current_coach.id} bloqueó {activity_type} el {session_date} de {start_time} a {end_time}")
        
        return jsonify({
            'success': True,
            'message': 'Tiempo bloqueado exitosamente',
            'session_id': block.id
        }), 200
        
    except ValueError as e:
        return jsonify({'error': f'Formato de fecha/hora inválido: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Error en api_coach_block_time: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error bloqueando tiempo: {str(e)}'}), 500

@app.route('/api/coach/direct-appointment', methods=['POST'])
@coach_session_required
def api_coach_direct_appointment():
    """Crear una cita directa con un coachee"""
    try:
        current_coach = g.current_user
        data = request.get_json() or {}
        
        # Validar datos requeridos
        coachee_id = data.get('coachee_id')
        title = data.get('title')
        session_date_str = data.get('session_date')
        start_time_str = data.get('start_time')
        end_time_str = data.get('end_time')
        location = data.get('location', 'Por definir')
        description = data.get('description', '')
        notification_message = data.get('notification_message', '')
        send_notification = data.get('send_notification', True)
        
        if not all([coachee_id, title, session_date_str, start_time_str, end_time_str]):
            return jsonify({'error': 'Faltan datos requeridos'}), 400
        
        logger.info(f"🔍 DIRECT-APPOINTMENT: Validando coachee_id={coachee_id} (tipo: {type(coachee_id)}) para coach {current_coach.id}")
        
        # Validar que el coachee existe y es del coach
        coachee = User.query.filter(
            User.id == coachee_id,
            User.coach_id == current_coach.id,
            User.role == 'coachee'
        ).first()
        
        if not coachee:
            # Debug: buscar el coachee sin filtros para ver qué pasa
            coachee_any = User.query.filter(User.id == coachee_id).first()
            if coachee_any:
                logger.warning(f"❌ DIRECT-APPOINTMENT: Coachee {coachee_id} existe pero NO cumple condiciones: coach_id={coachee_any.coach_id} (esperado: {current_coach.id}, match={coachee_any.coach_id == current_coach.id}), role={coachee_any.role} (match={coachee_any.role == 'coachee'}), is_active={coachee_any.is_active}")
            else:
                logger.warning(f"❌ DIRECT-APPOINTMENT: Coachee {coachee_id} NO existe en la base de datos")
            return jsonify({'error': 'Coachee no encontrado o no es tu coachee'}), 404
        
        logger.info(f"✅ DIRECT-APPOINTMENT: Coachee {coachee.username} (ID: {coachee.id}) validado correctamente")
        
        # Parsear fecha y horas
        from datetime import datetime as dt
        session_date = dt.strptime(session_date_str, '%Y-%m-%d').date()
        start_time = dt.strptime(start_time_str, '%H:%M').time()
        end_time = dt.strptime(end_time_str, '%H:%M').time()
        
        # Validar que la fecha no sea en el pasado
        santiago_today = get_santiago_today()
        if session_date < santiago_today:
            return jsonify({'error': 'No se puede agendar en fechas pasadas'}), 400
        
        # Validar que la hora de fin sea posterior a la de inicio
        if end_time <= start_time:
            return jsonify({'error': 'La hora de fin debe ser posterior a la hora de inicio'}), 400
        
        # Verificar que no haya conflictos de horario para el coach
        conflicts = CoachingSession.query.filter_by(
            coach_id=current_coach.id,
            session_date=session_date
        ).filter(
            CoachingSession.status.in_(['confirmed', 'proposed']),
            db.or_(
                db.and_(
                    CoachingSession.start_time < end_time,
                    CoachingSession.end_time > start_time
                )
            )
        ).all()
        
        if conflicts:
            return jsonify({'error': 'Ya tienes una sesión o bloqueo en ese horario'}), 400
        
        # Crear la cita directa — confirmada de inmediato porque la inicia el coach
        appointment = CoachingSession(
            coach_id=current_coach.id,
            coachee_id=coachee_id,
            session_date=session_date,
            start_time=start_time,
            end_time=end_time,
            status='confirmed',
            session_type='direct_appointment',
            title=title,
            description=description,
            location=location,
            notification_message=notification_message,
            created_by_coach=True
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        logger.info(f"✅ CITA DIRECTA: Coach {current_coach.id} agendó cita con coachee {coachee_id} para {session_date} de {start_time} a {end_time}")
        
        # TODO: Aquí se puede agregar lógica para enviar notificación al coachee
        # if send_notification:
        #     send_appointment_notification(coachee, appointment, notification_message)
        
        return jsonify({
            'success': True,
            'message': f'Cita confirmada con {coachee.full_name}',
            'session_id': appointment.id
        }), 200
        
    except ValueError as e:
        return jsonify({'error': f'Formato de fecha/hora inválido: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Error en api_coach_direct_appointment: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error creando cita: {str(e)}'}), 500

@app.route('/api/coach/session-requests-legacy/<int:request_id>/propose', methods=['POST'])
@coach_session_required
def api_coach_propose_session_time_legacy(request_id):
    """Proponer un horario alternativo para una solicitud de sesión (LEGACY - CoachingSession)"""
    try:
        current_coach = g.current_user
        data = request.get_json() or {}
        
        # Buscar la solicitud original
        original_session = CoachingSession.query.filter_by(
            id=request_id,
            coach_id=current_coach.id,
            status='pending'
        ).first()
        
        if not original_session:
            logger.warning(f"❌ PROPONER: Solicitud {request_id} no encontrada o no está pendiente")
            return jsonify({'error': 'Solicitud no encontrada'}), 404
        
        # Obtener datos de la propuesta
        proposed_date_str = data.get('proposed_date')
        proposed_start_time_str = data.get('proposed_start_time')
        proposed_end_time_str = data.get('proposed_end_time')
        message = data.get('message', '')
        
        if not all([proposed_date_str, proposed_start_time_str, proposed_end_time_str]):
            return jsonify({'error': 'Faltan datos requeridos'}), 400
        
        # Parsear fecha y horas
        from datetime import datetime as dt
        proposed_date = dt.strptime(proposed_date_str, '%Y-%m-%d').date()
        proposed_start_time = dt.strptime(proposed_start_time_str, '%H:%M').time()
        proposed_end_time = dt.strptime(proposed_end_time_str, '%H:%M').time()
        
        # Crear nueva sesión con status='proposed'
        proposed_session = CoachingSession(
            coach_id=current_coach.id,
            coachee_id=original_session.coachee_id,
            session_date=proposed_date,
            start_time=proposed_start_time,
            end_time=proposed_end_time,
            status='proposed',
            title=original_session.title,
            description=original_session.description,
            location=original_session.location,
            original_session_id=request_id,
            proposed_by='coach',
            proposal_message=message or f'El coach propone un nuevo horario: {proposed_date_str} de {proposed_start_time_str} a {proposed_end_time_str}'
        )
        
        db.session.add(proposed_session)
        
        # Cambiar status de la sesión original a 'proposed' para indicar que hay una propuesta pendiente
        original_session.status = 'proposed'
        original_session.notes = f"Coach propuso nuevo horario: {proposed_date_str} {proposed_start_time_str}-{proposed_end_time_str}"
        
        db.session.commit()
        
        logger.info(f"📅 PROPUESTA: Coach {current_coach.id} propuso horario alternativo para sesión {request_id}")
        logger.info(f"  Nueva sesión ID: {proposed_session.id}, Fecha: {proposed_date}, Hora: {proposed_start_time}-{proposed_end_time}")
        
        return jsonify({
            'success': True,
            'message': 'Propuesta enviada al coachee',
            'proposed_session_id': proposed_session.id
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coach_propose_session_time: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error al proponer horario: {str(e)}'}), 500

@app.route('/api/coach/session/<int:session_id>', methods=['PUT', 'DELETE'])
@coach_session_required
def api_coach_session_detail(session_id):
    """Modificar o cancelar una sesión específica"""
    try:
        current_coach = g.current_user
        
        session = CoachingSession.query.filter_by(
            id=session_id,
            coach_id=current_coach.id
        ).first()
        
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        
        if request.method == 'PUT':
            data = request.get_json()
            action = data.get('action')
            
            if action == 'propose_reschedule':
                # Proponer reagendamiento de sesión existente
                proposed_date = data.get('proposed_date')
                proposed_start_time = data.get('proposed_start_time')
                proposed_end_time = data.get('proposed_end_time')
                proposal_message = data.get('message', '')
                
                # Crear nueva propuesta
                new_proposal = CoachingSession(
                    coach_id=current_coach.id,
                    coachee_id=session.coachee_id,
                    session_date=datetime.strptime(proposed_date, '%Y-%m-%d').date(),
                    start_time=datetime.strptime(proposed_start_time, '%H:%M').time(),
                    end_time=datetime.strptime(proposed_end_time, '%H:%M').time(),
                    status='proposed',
                    title=session.title,
                    description=session.description,
                    location=session.location,
                    original_session_id=session.id,
                    proposed_by='coach',
                    proposal_message=proposal_message
                )
                
                db.session.add(new_proposal)
                session.status = 'proposal_sent'
                
                message = f'Propuesta de reagendamiento enviada: {proposed_date} a las {proposed_start_time}'
            
            elif action == 'update':
                # Actualizar detalles de la sesión
                if 'title' in data:
                    session.title = data['title']
                if 'description' in data:
                    session.description = data['description']
                if 'location' in data:
                    session.location = data['location']
                
                message = 'Sesión actualizada correctamente'
            
            else:
                return jsonify({'error': 'Acción no válida'}), 400
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': message
            }), 200
        
        elif request.method == 'DELETE':
            # Cancelar sesión
            session.status = 'cancelled'
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Sesión cancelada correctamente'
            }), 200
            
    except Exception as e:
        logger.error(f"Error en api_coach_session_detail: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error gestionando sesión: {str(e)}'}), 500

# ================================
# COACHEE CALENDAR APIs
# ================================

@app.route('/api/coachee/coach-availability', methods=['GET'])
@coachee_session_required
def api_coachee_coach_availability():
    """Ver disponibilidad del coach asignado"""
    try:
        current_coachee = g.current_user
        
        if not current_coachee.coach_id:
            return jsonify({'error': 'No tienes un coach asignado'}), 400
        
        # Obtener disponibilidad del coach
        availability = CoachAvailability.query.filter_by(
            coach_id=current_coachee.coach_id,
            is_active=True
        ).order_by(CoachAvailability.day_of_week, CoachAvailability.start_time).all()
        
        # Obtener sesiones existentes para bloquear horarios ocupados (solo futuras)
        # IMPORTANTE: Incluye self_activity (bloqueos personales) y todas las sesiones confirmed/pending
        today = get_santiago_today()
        future_date = today + timedelta(days=7)  # Próximos 7 días
        
        occupied_sessions = CoachingSession.query.filter_by(
            coach_id=current_coachee.coach_id
        ).filter(
            CoachingSession.status.in_(['confirmed', 'pending', 'proposed']),
            CoachingSession.session_date >= today,
            CoachingSession.session_date <= future_date
        ).order_by(CoachingSession.session_date, CoachingSession.start_time).all()
        
        logger.info(f"🗓️ DISPONIBILIDAD: Coach {current_coachee.coach_id}, período {today} a {future_date}")
        logger.info(f"📅 DISPONIBILIDAD: {len(availability)} horarios generales, {len(occupied_sessions)} sesiones ocupadas (incluye bloqueos personales)")
        
        availability_data = []
        for slot in availability:
            availability_data.append({
                'id': slot.id,
                'day_of_week': slot.day_of_week,
                'start_time': slot.start_time.strftime('%H:%M'),
                'end_time': slot.end_time.strftime('%H:%M'),
                'is_active': slot.is_active
            })
        
        occupied_data = []
        for session in occupied_sessions:
            occupied_data.append({
                'date': session.session_date.isoformat(),
                'start_time': session.start_time.strftime('%H:%M'),
                'end_time': session.end_time.strftime('%H:%M'),
                'status': session.status
            })
        
        return jsonify({
            'success': True,
            'availability': availability_data,
            'occupied_slots': occupied_data,
            'coach_name': current_coachee.coach.full_name if current_coachee.coach else 'Sin coach'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_coach_availability: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo disponibilidad: {str(e)}'}), 500

@app.route('/api/coachee/request-session', methods=['POST'])
@coachee_session_required
def api_coachee_request_session():
    """Solicitar nueva sesión con el coach"""
    try:
        current_coachee = g.current_user
        
        if not current_coachee.coach_id:
            return jsonify({'error': 'No tienes un coach asignado'}), 400
        
        data = request.get_json()
        session_date = data.get('session_date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        title = data.get('title', 'Sesión de Coaching')
        description = data.get('description', '')
        location = data.get('location', 'Por definir')
        
        if not all([session_date, start_time, end_time]):
            return jsonify({'error': 'Fecha y horarios son requeridos'}), 400
        
        # Verificar que la fecha no sea en el pasado (usando zona horaria de Santiago)
        requested_date = datetime.strptime(session_date, '%Y-%m-%d').date()
        santiago_today = get_santiago_today()
        if requested_date < santiago_today:
            return jsonify({'error': 'No se puede agendar en fechas pasadas'}), 400
        
        # Verificar disponibilidad del horario
        # Convertir a formato JavaScript: 0=Domingo, 1=Lunes, ..., 6=Sábado
        day_of_week = (requested_date.weekday() + 1) % 7
        
        start_time_obj = datetime.strptime(start_time, '%H:%M').time()
        end_time_obj = datetime.strptime(end_time, '%H:%M').time()
        
        # Verificar que el coach esté disponible en ese día y horario
        availability = CoachAvailability.query.filter_by(
            coach_id=current_coachee.coach_id,
            day_of_week=day_of_week,
            is_active=True
        ).filter(
            CoachAvailability.start_time <= start_time_obj,
            CoachAvailability.end_time >= end_time_obj
        ).first()
        
        if not availability:
            return jsonify({'error': 'El coach no está disponible en ese horario'}), 400
        
        # Verificar que no haya conflicto con sesiones existentes
        conflict = CoachingSession.query.filter_by(
            coach_id=current_coachee.coach_id,
            session_date=requested_date
        ).filter(
            CoachingSession.status.in_(['confirmed', 'pending', 'proposed']),
            CoachingSession.start_time < end_time_obj,
            CoachingSession.end_time > start_time_obj
        ).first()
        
        if conflict:
            return jsonify({'error': 'Ya existe una sesión programada en ese horario'}), 400
        
        # Crear nueva solicitud de sesión
        new_session = CoachingSession(
            coach_id=current_coachee.coach_id,
            coachee_id=current_coachee.id,
            session_date=requested_date,
            start_time=start_time_obj,
            end_time=end_time_obj,
            status='pending',
            title=title,
            description=description,
            location=location,
            proposed_by='coachee'
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        logger.info(f"✅ SOLICITUD CREADA: Coachee {current_coachee.id} ({current_coachee.full_name}) → Coach {current_coachee.coach_id}")
        logger.info(f"   Fecha: {requested_date}, Hora: {start_time_obj}-{end_time_obj}")
        logger.info(f"   Título: {title}, ID: {new_session.id}")
        
        # Crear notificación para el coach
        create_notification(
            user_id=current_coachee.coach_id,
            type='session_request',
            title='Nueva solicitud de sesión',
            message=f'{current_coachee.full_name} ha solicitado una sesión para el {requested_date.strftime("%d/%m/%Y")} a las {start_time}',
            related_id=new_session.id,
            related_type='session'
        )
        
        return jsonify({
            'success': True,
            'message': f'Solicitud enviada para {session_date} a las {start_time}',
            'session_id': new_session.id
        }), 201
        
    except Exception as e:
        logger.error(f"Error en api_coachee_request_session: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error creando solicitud: {str(e)}'}), 500

@app.route('/api/coachee/my-sessions', methods=['GET'])
@coachee_session_required
def api_coachee_my_sessions():
    """Ver mis sesiones programadas y solicitudes"""
    try:
        current_coachee = g.current_user
        
        # Parámetros de filtrado
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # 1. Obtener sesiones de CoachingSession (legacy)
        query = CoachingSession.query.filter_by(coachee_id=current_coachee.id)
        
        if start_date:
            date_part = start_date.split('T')[0] if 'T' in start_date else start_date
            query = query.filter(CoachingSession.session_date >= datetime.strptime(date_part, '%Y-%m-%d').date())
        if end_date:
            date_part = end_date.split('T')[0] if 'T' in end_date else end_date
            query = query.filter(CoachingSession.session_date <= datetime.strptime(date_part, '%Y-%m-%d').date())
        
        sessions = query.order_by(
            CoachingSession.session_date.desc(), 
            CoachingSession.start_time.desc()
        ).all()
        
        sessions_data = []
        for session in sessions:
            # Construir datetime de forma segura
            start_datetime = None
            end_datetime = None
            if session.session_date and session.start_time:
                try:
                    start_datetime = datetime.combine(session.session_date, session.start_time).isoformat()
                except Exception as e:
                    logger.warning(f"Error combinando fecha/hora para sesión {session.id}: {str(e)}")
            
            if session.session_date and session.end_time:
                try:
                    end_datetime = datetime.combine(session.session_date, session.end_time).isoformat()
                except Exception as e:
                    logger.warning(f"Error combinando fecha/hora fin para sesión {session.id}: {str(e)}")
            
            sessions_data.append({
                'id': session.id,
                'type': 'coaching_session',
                'coach_name': session.coach.full_name if session.coach else 'Sin coach',
                'session_date': session.session_date.isoformat() if session.session_date else None,
                'start_time': session.start_time.strftime('%H:%M') if session.start_time else None,
                'end_time': session.end_time.strftime('%H:%M') if session.end_time else None,
                'status': session.status,
                'title': session.title,
                'description': session.description,
                'location': session.location,
                'start': start_datetime,
                'end': end_datetime,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'original_session_id': session.original_session_id,
                'proposed_by': session.proposed_by,
                'proposal_message': session.proposal_message,
                'created_by_coach': session.created_by_coach or False,
                'notification_message': session.notification_message
            })
        
        # 2. Obtener solicitudes de SessionRequest (nuevo sistema)
        session_requests = SessionRequest.query.filter_by(
            coachee_id=current_coachee.id
        ).filter(
            SessionRequest.status.in_(['pending', 'contacted', 'scheduled'])
        ).order_by(
            SessionRequest.created_at.desc()
        ).all()
        
        for req in session_requests:
            # Obtener nombre del coach asignado
            coach_name = 'Pendiente de asignación'
            if req.assigned_coach_id:
                coach = User.query.get(req.assigned_coach_id)
                coach_name = coach.full_name if coach else 'Coach asignado'
            
            sessions_data.append({
                'id': req.id,
                'type': 'session_request',
                'coach_name': coach_name,
                'session_date': None,  # No tiene fecha fija aún
                'start_time': None,
                'end_time': None,
                'status': req.status,
                'title': f'Solicitud de sesión - {req.session_type}' if req.session_type else 'Solicitud de sesión',
                'description': req.message,
                'location': 'Por coordinar',
                'created_at': req.created_at.isoformat() if req.created_at else None,
                'availability': req.availability,
                'preferred_method': req.preferred_method,
                'coach_notes': req.coach_notes,
                'contacted_at': req.contacted_at.isoformat() if req.contacted_at else None,
                'session_type': req.session_type
            })
        
        return jsonify({
            'success': True,
            'sessions': sessions_data,
            'total': len(sessions_data)
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_my_sessions: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error obteniendo sesiones: {str(e)}'}), 500

@app.route('/api/coachee/session/<int:session_id>', methods=['PUT'])
@coachee_session_required
def api_coachee_session_detail(session_id):
    """Responder a propuestas del coach"""
    try:
        current_coachee = g.current_user
        
        session = CoachingSession.query.filter_by(
            id=session_id,
            coachee_id=current_coachee.id
        ).first()
        
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        
        data = request.get_json()
        action = data.get('action')  # 'accept_proposal', 'reject_proposal', 'accept_direct', 'reject_direct'
        
        if action == 'accept_proposal' and session.status == 'proposed':
            # Aceptar propuesta del coach
            session.status = 'confirmed'
            
            # Si hay una sesión original, cancelarla
            if session.original_session_id:
                original = CoachingSession.query.get(session.original_session_id)
                if original:
                    original.status = 'cancelled'
            
            message = 'Propuesta aceptada. Sesión confirmada.'
        
        elif action == 'reject_proposal' and session.status == 'proposed':
            # Rechazar propuesta del coach
            session.status = 'cancelled'
            
            # Si hay una sesión original, reactivarla como pendiente
            if session.original_session_id:
                original = CoachingSession.query.get(session.original_session_id)
                if original:
                    original.status = 'pending'
            
            message = 'Propuesta rechazada.'
        
        elif action == 'accept_direct' and session.status == 'pending' and session.created_by_coach:
            # Aceptar cita directa creada por el coach
            session.status = 'confirmed'
            logger.info(f"✅ CITA-DIRECTA: Coachee {current_coachee.id} aceptó cita {session_id} del coach {session.coach_id}")
            message = 'Cita aceptada y confirmada en tu calendario.'
        
        elif action == 'reject_direct' and session.status == 'pending' and session.created_by_coach:
            # Rechazar cita directa creada por el coach
            session.status = 'cancelled'
            logger.info(f"❌ CITA-DIRECTA: Coachee {current_coachee.id} rechazó cita {session_id} del coach {session.coach_id}")
            message = 'Cita rechazada.'
        
        else:
            return jsonify({'error': 'Acción no válida o estado incorrecto'}), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': message
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_session_detail: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error gestionando sesión: {str(e)}'}), 500


@app.route('/api/coachee/session-request/<int:request_id>/acknowledge', methods=['POST'])
@coachee_session_required
def api_coachee_acknowledge_session_request(request_id):
    """Coachee reconoce y acepta la respuesta del coach"""
    try:
        current_coachee = g.current_user
        
        # Buscar la solicitud
        session_request = SessionRequest.query.filter_by(
            id=request_id,
            coachee_id=current_coachee.id
        ).first()
        
        if not session_request:
            return jsonify({'error': 'Solicitud no encontrada'}), 404
        
        # Actualizar estado a 'scheduled' (coordinado)
        session_request.status = 'scheduled'
        session_request.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"✅ SOLICITUD-ACK: Coachee {current_coachee.username} confirmó coordinación de SessionRequest {request_id}")
        
        return jsonify({
            'success': True,
            'message': 'Solicitud marcada como coordinada'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en api_coachee_acknowledge_session_request: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error actualizando solicitud: {str(e)}'}), 500


@app.route('/api/coachee/request-development-plan', methods=['POST'])
def request_development_plan():
    """Endpoint para que el coachee solicite un plan de desarrollo al coach"""
    try:
        current_coachee = get_current_coachee()
        if not current_coachee:
            return jsonify({'error': 'No autorizado'}), 401
        
        data = request.get_json()
        evaluation_id = data.get('evaluation_id')
        message = data.get('message', 'Solicito un plan de desarrollo personalizado.')
        priority = data.get('priority', 'medium')
        focus_areas = data.get('focus_areas', [])
        goals = data.get('goals', '')
        
        if not evaluation_id:
            return jsonify({'error': 'ID de evaluación requerido'}), 400
        
        # Verificar que la evaluación pertenece al coachee
        evaluation = AssessmentResult.query.filter_by(
            id=evaluation_id,
            user_id=current_coachee.id
        ).first()
        
        if not evaluation:
            return jsonify({'error': 'Evaluación no encontrada'}), 404
        
        # Obtener título de la evaluación
        assessment = Assessment.query.get(evaluation.assessment_id)
        assessment_title = assessment.title if assessment else 'Evaluación'
        
        # Crear descripción estructurada con metadata JSON
        import json
        metadata = {
            'priority': priority,
            'focus_areas': focus_areas,
            'goals': goals,
            'evaluation_id': evaluation_id,
            'score': evaluation.score
        }
        
        # Crear tarea para el coach
        if current_coachee.coach_id:
            new_task = Task(
                coach_id=current_coachee.coach_id,
                coachee_id=current_coachee.id,
                title=f"Plan de Desarrollo: {assessment_title}",
                description=f"Solicitud de plan de desarrollo de {current_coachee.full_name or current_coachee.username}\n\n{message}\n\n__METADATA__\n{json.dumps(metadata)}\n__END_METADATA__",
                category='development_plan_request',
                priority=priority,
                is_active=True
            )
            db.session.add(new_task)
            db.session.commit()
            
            logger.info(f"📋 DEVELOPMENT PLAN REQUEST: Created task {new_task.id} for coach {current_coachee.coach_id}")
        
        logger.info(f"📋 DEVELOPMENT PLAN REQUEST: Coachee {current_coachee.username} (ID: {current_coachee.id}) "
                   f"requested development plan for evaluation {evaluation_id}")
        logger.info(f"📋 PRIORITY: {priority}, FOCUS AREAS: {focus_areas}, GOALS: {goals}")
        logger.info(f"📋 MESSAGE: {message}")
        logger.info(f"📋 EVALUATION: Assessment ID: {evaluation.assessment_id}, Score: {evaluation.score}")
        
        return jsonify({
            'success': True,
            'message': 'Solicitud de plan de desarrollo enviada exitosamente'
        })
        
    except Exception as e:
        logger.error(f"Error en request_development_plan: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': f'Error procesando solicitud: {str(e)}'}), 500

@app.route('/api/coachee/contact-coach-session', methods=['POST'])
def contact_coach_session():
    """Endpoint para que el coachee solicite una sesión gratuita con un coach"""
    try:
        current_coachee = get_current_coachee()
        if not current_coachee:
            return jsonify({'error': 'No autorizado'}), 401
        
        data = request.get_json()
        evaluation_id = data.get('evaluation_id')
        session_type = data.get('session_type', 'free_consultation')
        
        logger.info(f"🔍 DEBUG - Received evaluation_id: {evaluation_id} (type: {type(evaluation_id).__name__})")
        
        # Verificar que la evaluación pertenece al coachee (si se proporciona y no es null)
        evaluation = None
        if evaluation_id and evaluation_id != 'null' and evaluation_id is not None:
            logger.info(f"🔍 DEBUG - Querying evaluation with ID: {evaluation_id} for user: {current_coachee.id}")
            
            # Buscar primero en AssessmentHistory (incluye todos los intentos históricos)
            evaluation = AssessmentHistory.query.filter_by(
                id=evaluation_id,
                user_id=current_coachee.id
            ).first()
            
            # Si no se encuentra, buscar en AssessmentResult (solo resultados activos)
            if not evaluation:
                evaluation = AssessmentResult.query.filter_by(
                    id=evaluation_id,
                    user_id=current_coachee.id
                ).first()
            
            if not evaluation:
                logger.warning(f"❌ Evaluation ID {evaluation_id} not found for coachee {current_coachee.id}")
                # Listar las evaluaciones disponibles para debug
                available_history = AssessmentHistory.query.filter_by(user_id=current_coachee.id).all()
                available_results = AssessmentResult.query.filter_by(user_id=current_coachee.id).all()
                logger.info(f"📋 Available in history: {[e.id for e in available_history]}")
                logger.info(f"📋 Available in results: {[e.id for e in available_results]}")
                return jsonify({'error': 'Evaluación no encontrada'}), 404
            else:
                logger.info(f"✅ Evaluation found: {evaluation.id} (from {'history' if isinstance(evaluation, AssessmentHistory) else 'results'})")
        else:
            evaluation_id = None
            logger.info(f"ℹ️ No evaluation provided or null value")
        
        # Extraer contact_data (nuevo formato) o message (formato legacy)
        contact_data = data.get('contact_data', {})
        if contact_data:
            # Nuevo formato con datos estructurados
            name = contact_data.get('name', current_coachee.full_name)
            email = contact_data.get('email', current_coachee.email)
            phone = contact_data.get('phone', '')
            whatsapp = contact_data.get('whatsapp', phone)
            preferred_method = contact_data.get('preferred_method', 'email')
            availability = contact_data.get('availability', '')
            message = contact_data.get('message', 'Solicito una sesión gratuita de 30 minutos.')
        else:
            # Formato legacy (compatibilidad hacia atrás)
            name = current_coachee.full_name
            email = current_coachee.email
            phone = ''
            whatsapp = ''
            preferred_method = 'email'
            availability = ''
            message = data.get('message', 'Solicito una sesión gratuita de 30 minutos.')
        
        # Loggear la solicitud de sesión gratuita con información detallada
        logger.info(f"🎯 FREE SESSION REQUEST: Coachee {current_coachee.username} (ID: {current_coachee.id}) "
                   f"requested {session_type} session")
        logger.info(f"📧 CONTACT INFO: Name: {name}, Email: {email}, Phone: {phone}, WhatsApp: {whatsapp}")
        logger.info(f"📞 PREFERRED METHOD: {preferred_method}")
        if availability:
            logger.info(f"🕐 AVAILABILITY: {availability}")
        logger.info(f"💬 MESSAGE: {message}")
        if evaluation_id and evaluation:
            logger.info(f"📊 RELATED EVALUATION: ID {evaluation_id}, Assessment ID: {evaluation.assessment_id}, Score: {evaluation.score}")
        else:
            logger.info(f"📊 NO EVALUATION PROVIDED - General session request")
        
        # Guardar la solicitud en la base de datos
        try:
            session_request = SessionRequest(
                coachee_id=current_coachee.id,
                evaluation_id=evaluation_id,
                session_type=session_type,
                name=name,
                email=email,
                phone=phone,
                whatsapp=whatsapp,
                preferred_method=preferred_method,
                availability=availability,
                message=message,
                status='pending'
            )
            
            db.session.add(session_request)
            db.session.commit()
            
            logger.info(f"✅ Session request saved with ID: {session_request.id}")
            
        except Exception as db_error:
            db.session.rollback()
            logger.error(f"❌ Error saving session request: {str(db_error)}", exc_info=True)
            # Continuar aunque falle el guardado (fallback a logs)
        
        return jsonify({
            'success': True,
            'message': 'Solicitud de sesión gratuita enviada exitosamente'
        })
        
    except Exception as e:
        logger.error(f"Error en contact_coach_session: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error procesando solicitud: {str(e)}'}), 500

# ===== ENDPOINTS DE DOCUMENTOS PARA COACHEES =====

@app.route('/api/coachee/documents', methods=['GET'])
@coachee_session_required
def api_coachee_documents():
    """Obtener documentos asignados al coachee"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        if not current_coachee or current_coachee.role != 'coachee':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Obtener documentos asignados al coachee
        documents = db.session.query(Document).filter(
            Document.coachee_id == current_coachee.id,
            Document.is_active == True
        ).order_by(Document.uploaded_at.desc()).all()
        
        documents_data = []
        for doc in documents:
            # Obtener archivos del documento
            files_data = []
            for file in doc.files:
                files_data.append({
                    'id': file.id,
                    'filename': file.original_filename,
                    'size': file.file_size,
                    'mime_type': file.mime_type
                })
            
            documents_data.append({
                'id': doc.id,
                'title': doc.title,
                'description': doc.description,
                'category': doc.category,
                'priority': doc.priority,
                'uploaded_at': doc.uploaded_at.isoformat(),
                'uploaded_by': doc.coach.full_name if doc.coach else 'Coach',
                'files': files_data
            })
        
        return jsonify({
            'success': True,
            'documents': documents_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos del coachee: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al obtener documentos: {str(e)}'}), 500

@app.route('/api/coachee/documents/<int:document_id>/files/<int:file_id>/preview', methods=['GET'])
@coachee_session_required
def api_coachee_document_preview(document_id, file_id):
    """Vista previa de un archivo de documento"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        if not current_coachee or current_coachee.role != 'coachee':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que el documento pertenece al coachee
        document = Document.query.filter_by(
            id=document_id,
            coachee_id=current_coachee.id,
            is_active=True
        ).first()
        
        if not document:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        # Obtener el archivo
        doc_file = DocumentFile.query.filter_by(
            id=file_id,
            document_id=document_id
        ).first()
        
        if not doc_file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Obtener archivo desde S3 o sistema de archivos local
        if USE_S3 and doc_file.file_path.startswith('https://'):
            # Redirigir a la URL de S3
            from flask import redirect
            return redirect(doc_file.file_path)
        else:
            # Verificar que el archivo existe localmente
            if not os.path.exists(doc_file.file_path):
                return jsonify({'error': 'Archivo no encontrado en el servidor'}), 404
            
            # Devolver el archivo
            return send_file(
                doc_file.file_path,
                mimetype=doc_file.mime_type,
                as_attachment=False,
                download_name=doc_file.original_filename
            )
        
    except Exception as e:
        logger.error(f"Error en vista previa de documento: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al obtener vista previa: {str(e)}'}), 500

@app.route('/api/coachee/documents/<int:document_id>/files/<int:file_id>/download', methods=['GET'])
@coachee_session_required
def api_coachee_document_download(document_id, file_id):
    """Descarga de un archivo de documento"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        if not current_coachee or current_coachee.role != 'coachee':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que el documento pertenece al coachee
        document = Document.query.filter_by(
            id=document_id,
            coachee_id=current_coachee.id,
            is_active=True
        ).first()
        
        if not document:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        # Obtener el archivo
        doc_file = DocumentFile.query.filter_by(
            id=file_id,
            document_id=document_id
        ).first()
        
        if not doc_file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Obtener archivo desde S3 o sistema de archivos local
        if USE_S3 and doc_file.file_path.startswith('https://'):
            # Redirigir a la URL de S3 para descarga
            from flask import redirect
            return redirect(doc_file.file_path)
        else:
            # Verificar que el archivo existe localmente
            if not os.path.exists(doc_file.file_path):
                return jsonify({'error': 'Archivo no encontrado en el servidor'}), 404
            
            # Devolver el archivo para descarga
            return send_file(
                doc_file.file_path,
                mimetype=doc_file.mime_type,
                as_attachment=True,
                download_name=doc_file.original_filename
            )
        
    except Exception as e:
        logger.error(f"Error descargando documento: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al descargar archivo: {str(e)}'}), 500

@app.route('/api/coach/documents/<int:document_id>/download', methods=['GET'])
@coach_session_required
def api_coach_document_download(document_id):
    """Descarga de documento para coaches"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que el documento pertenece al coach
        document = Document.query.filter_by(
            id=document_id,
            coach_id=current_coach.id,
            is_active=True
        ).first()
        
        if not document:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        # Obtener el archivo (asumiendo que hay uno por documento)
        doc_file = DocumentFile.query.filter_by(
            document_id=document_id
        ).first()
        
        if not doc_file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Obtener archivo desde S3 o sistema de archivos local
        if USE_S3 and doc_file.file_path.startswith('https://'):
            # Redirigir a la URL de S3 para descarga
            from flask import redirect
            return redirect(doc_file.file_path)
        else:
            # Verificar que el archivo existe localmente
            if not os.path.exists(doc_file.file_path):
                return jsonify({'error': 'Archivo no encontrado en el servidor'}), 404
            
            # Devolver el archivo para descarga
            return send_file(
                doc_file.file_path,
                mimetype=doc_file.mime_type,
                as_attachment=True,
                download_name=doc_file.original_filename
            )
        
    except Exception as e:
        logger.error(f"Error descargando documento: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al descargar archivo: {str(e)}'}), 500

@app.route('/api/coach/documents/<int:document_id>/view', methods=['GET'])
@coach_session_required
def api_coach_document_view(document_id):
    """Vista previa de documento para coaches - Para usar con PDF.js en feed"""
    try:
        current_coach = getattr(g, 'current_user', None)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que el documento pertenece al coach O está asignado a un coachee del coach
        document = Document.query.filter_by(
            id=document_id,
            is_active=True
        ).first()
        
        if not document:
            logger.error(f"❌ Documento {document_id} no existe o no está activo")
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        logger.info(f"📄 Coach {current_coach.id} intentando acceder a documento {document_id} (coach_id={document.coach_id}, coachee_id={document.coachee_id})")
        
        # Verificar permisos: el coach debe ser el dueño O el documento debe estar en un Content asignado por el coach
        has_permission = False
        
        if document.coach_id == current_coach.id:
            # El coach es el dueño del documento
            has_permission = True
            logger.info(f"✅ Coach {current_coach.id} es el dueño del documento {document_id}")
        else:
            # Verificar si el documento está en algún Content asignado por este coach
            content_with_doc = Content.query.filter(
                Content.coach_id == current_coach.id,
                Content.content_type == 'document',
                Content.content_url.like(f'%/documents/{document_id}/%'),
                Content.is_active == True
            ).first()
            
            if content_with_doc:
                has_permission = True
                logger.info(f"✅ Coach {current_coach.id} tiene acceso al documento {document_id} vía Content ID {content_with_doc.id}")
            else:
                # También verificar por coachee_id
                if document.coachee_id:
                    coachee = User.query.filter_by(
                        id=document.coachee_id,
                        coach_id=current_coach.id,
                        role='coachee'
                    ).first()
                    if coachee:
                        has_permission = True
                        logger.info(f"✅ Coach {current_coach.id} accediendo a documento {document_id} de su coachee {document.coachee_id}")
                    else:
                        logger.warning(f"❌ El coachee {document.coachee_id} del documento {document_id} NO pertenece al coach {current_coach.id}")
                else:
                    logger.warning(f"❌ Documento {document_id} no tiene coachee_id asignado y el coach {current_coach.id} no es el dueño")
        
        if not has_permission:
            logger.warning(f"❌ PERMISO DENEGADO: Coach {current_coach.id} sin permisos para documento {document_id}")
            return jsonify({'error': 'No tienes permisos para ver este documento'}), 403
        
        # Obtener el archivo (asumiendo que hay uno por documento)
        doc_file = DocumentFile.query.filter_by(
            document_id=document_id
        ).first()
        
        if not doc_file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Obtener archivo desde S3 o sistema de archivos local
        if USE_S3 and doc_file.file_path.startswith('https://'):
            # Redirigir a la URL de S3 con headers CORS
            from flask import redirect
            return redirect(doc_file.file_path)
        else:
            # Verificar que el archivo existe localmente
            if not os.path.exists(doc_file.file_path):
                return jsonify({'error': 'Archivo no encontrado en el servidor'}), 404
            
            logger.info(f"Coach {current_coach.id} viendo preview de documento {document_id}")
            
            # Devolver el archivo para preview (no descarga)
            response = send_file(
                doc_file.file_path,
                mimetype=doc_file.mime_type,
                as_attachment=False,  # Preview en navegador
                download_name=doc_file.original_filename
            )
            
            # Agregar headers CORS para permitir carga desde PDF.js
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            
            return response
        
    except Exception as e:
        logger.error(f"Error viendo preview de documento: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al cargar archivo: {str(e)}'}), 500

@app.route('/api/coachee/assigned-documents/<int:document_id>/download', methods=['GET'])
@coachee_session_required
def api_coachee_assigned_document_download(document_id):
    """Descarga de documento asignado por coach para coachees"""
    try:
        current_coachee = getattr(g, 'current_user', None)
        if not current_coachee or current_coachee.role != 'coachee':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # Verificar que el coachee tiene un documento asignado por contenido
        content = Content.query.filter_by(
            coachee_id=current_coachee.id,
            content_type='document'
        ).filter(Content.content_url.like(f'%/{document_id}/download%')).first()
        
        if not content:
            return jsonify({'error': 'Documento no asignado o no encontrado'}), 404
        
        # Verificar que el documento existe y pertenece a un coach
        document = Document.query.filter_by(
            id=document_id,
            is_active=True
        ).first()
        
        if not document:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        # Obtener el archivo (tomar el primero disponible)
        doc_file = DocumentFile.query.filter_by(
            document_id=document_id
        ).first()
        
        if not doc_file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Obtener archivo desde S3 o sistema de archivos local
        if USE_S3 and doc_file.file_path.startswith('https://'):
            # Redirigir a la URL de S3 para preview
            from flask import redirect
            return redirect(doc_file.file_path)
        else:
            # Verificar que el archivo existe localmente
            if not os.path.exists(doc_file.file_path):
                return jsonify({'error': 'Archivo no encontrado en el servidor'}), 404
            
            logger.info(f"Coachee {current_coachee.id} descargando documento asignado {document_id}")
            
            # Devolver el archivo para descarga/preview
            return send_file(
                doc_file.file_path,
                mimetype=doc_file.mime_type,
                as_attachment=False,  # Para permitir preview en navegador
                download_name=doc_file.original_filename
            )
        
    except Exception as e:
        logger.error(f"Error descargando documento asignado: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error al descargar archivo: {str(e)}'}), 500

# ============================================================================
# MÓDULO EFECTOCOACH - DEMO MODE (SIN GUARDAR EN BD)
# ============================================================================

@app.route('/efectocoach')
def efectocoach_demo():
    """
    Página principal del módulo EfectoCoach en modo demo.
    No requiere autenticación ni guarda datos en BD.
    """
    try:
        logger.info("🎯 EFECTOCOACH: Acceso a página demo")
        return render_template('efectocoach_demo.html')
    except Exception as e:
        logger.error(f"❌ EFECTOCOACH: Error renderizando página: {e}")
        return "Error cargando la página de demo", 500

@app.route('/api/efectocoach/questions', methods=['GET'])
def api_efectocoach_questions():
    """
    API para obtener las preguntas de la evaluación demo.
    Retorna preguntas hardcoded sin acceder a la BD.
    """
    try:
        # Verificar que estamos en modo demo
        if not es_modo_demo(request):
            logger.warning("⚠️ EFECTOCOACH: Intento de acceso fuera de modo demo")
            return jsonify({
                'success': False,
                'error': 'Esta API solo está disponible en modo demo'
            }), 403
        
        logger.info("📊 EFECTOCOACH: Obteniendo preguntas demo")
        
        # Obtener preguntas desde memoria (sin BD)
        preguntas = obtener_preguntas_demo()
        
        return jsonify({
            'success': True,
            'questions': preguntas,
            'total': len(preguntas),
            'demo_mode': True
        })
        
    except Exception as e:
        logger.error(f"❌ EFECTOCOACH: Error obteniendo preguntas: {e}")
        return jsonify({
            'success': False,
            'error': 'Error cargando preguntas'
        }), 500

@app.route('/api/efectocoach/calculate', methods=['POST'])
def api_efectocoach_calculate():
    """
    API para calcular resultados en modo demo.
    Procesa respuestas SOLO en memoria, sin guardar en BD.
    """
    try:
        # Verificar que estamos en modo demo
        if not es_modo_demo(request):
            logger.warning("⚠️ EFECTOCOACH: Intento de cálculo fuera de modo demo")
            return jsonify({
                'success': False,
                'error': 'Esta API solo está disponible en modo demo'
            }), 403
        
        data = request.get_json()
        if not data or 'responses' not in data:
            return jsonify({
                'success': False,
                'error': 'Respuestas requeridas'
            }), 400
        
        responses = data.get('responses', {})
        
        logger.info(f"📊 EFECTOCOACH: Calculando resultados demo ({len(responses)} respuestas)")
        logger.info("🚫 EFECTOCOACH: MODO DEMO - No se guardará nada en BD")
        
        # Calcular puntaje en memoria (sin BD)
        score, result_text, dimensional_scores = calcular_puntaje_demo(responses)
        
        logger.info(f"✅ EFECTOCOACH: Resultados calculados - Score: {score}")
        
        # IMPORTANTE: No hacer ningún INSERT, UPDATE ni COMMIT a la BD
        # Los datos se procesan y retornan solo en memoria
        
        return jsonify({
            'success': True,
            'score': score,
            'result_text': result_text,
            'dimensional_scores': dimensional_scores,
            'demo_mode': True,
            'data_saved': False,  # Indicador explícito de que NO se guardó
            'message': 'Resultados calculados en memoria. No se guardó ningún dato.'
        })
        
    except Exception as e:
        logger.error(f"❌ EFECTOCOACH: Error calculando resultados: {e}")
        return jsonify({
            'success': False,
            'error': 'Error procesando resultados'
        }), 500

# ============================================================================
# FIN MÓDULO EFECTOCOACH
# ============================================================================

# ============================================================================
# MÓDULO TESTPERSONAL - DEMO MODE (SIN GUARDAR EN BD)
# ============================================================================

@app.route('/testpersonal')
def testpersonal_demo():
    """
    Página principal del módulo TestPersonal en modo demo.
    Evaluación de 4 áreas de vida con respuestas Sí/No.
    No requiere autenticación ni guarda datos en BD.
    """
    try:
        logger.info("🎯 TESTPERSONAL: Acceso a página demo")
        return render_template('testpersonal_demo.html')
    except Exception as e:
        logger.error(f"❌ TESTPERSONAL: Error renderizando página: {e}")
        return "Error cargando la página de demo", 500

@app.route('/api/testpersonal/questions', methods=['GET'])
def api_testpersonal_questions():
    """
    API para obtener las 20 afirmaciones de TestPersonal.
    Retorna preguntas hardcoded sin acceder a la BD.
    """
    try:
        # Verificar que estamos en modo demo
        if not es_modo_demo_personal(request):
            logger.warning("⚠️ TESTPERSONAL: Intento de acceso fuera de modo demo")
            return jsonify({
                'success': False,
                'error': 'Esta API solo está disponible en modo demo'
            }), 403
        
        logger.info("📊 TESTPERSONAL: Obteniendo preguntas demo")
        
        # Obtener preguntas desde memoria (sin BD)
        preguntas = obtener_preguntas_testpersonal()
        
        return jsonify({
            'success': True,
            'questions': preguntas,
            'total': len(preguntas),
            'demo_mode': True
        })
        
    except Exception as e:
        logger.error(f"❌ TESTPERSONAL: Error obteniendo preguntas: {e}")
        return jsonify({
            'success': False,
            'error': 'Error cargando preguntas'
        }), 500

@app.route('/api/testpersonal/calculate', methods=['POST'])
def api_testpersonal_calculate():
    """
    API para calcular resultados de TestPersonal en modo demo.
    Procesa respuestas SOLO en memoria, sin guardar en BD.
    """
    try:
        # Verificar que estamos en modo demo
        if not es_modo_demo_personal(request):
            logger.warning("⚠️ TESTPERSONAL: Intento de cálculo fuera de modo demo")
            return jsonify({
                'success': False,
                'error': 'Esta API solo está disponible en modo demo'
            }), 403
        
        data = request.get_json()
        if not data or 'responses' not in data:
            return jsonify({
                'success': False,
                'error': 'Respuestas requeridas'
            }), 400
        
        responses = data.get('responses', {})
        
        logger.info(f"📊 TESTPERSONAL: Calculando resultados demo ({len(responses)} respuestas)")
        logger.info("🚫 TESTPERSONAL: MODO DEMO - No se guardará nada en BD")
        
        # Calcular puntaje en memoria (sin BD)
        overall_score, overall_percentage, result_text, area_scores = calcular_puntaje_testpersonal(responses)
        
        # Obtener colores e interpretaciones por área
        area_details = {}
        for area, score in area_scores.items():
            area_details[area] = {
                'score': score,
                'max_score': 5,
                'color': obtener_color_area(score),
                'interpretation': obtener_interpretacion_area(area, score)
            }
        
        logger.info(f"✅ TESTPERSONAL: Resultados calculados - Puntaje: {overall_score}/20 ({overall_percentage}%)")
        
        # IMPORTANTE: No hacer ningún INSERT, UPDATE ni COMMIT a la BD
        # Los datos se procesan y retornan solo en memoria
        
        return jsonify({
            'success': True,
            'overall_score': overall_score,
            'overall_percentage': overall_percentage,
            'max_score': 20,
            'result_text': result_text,
            'area_scores': area_scores,
            'area_details': area_details,
            'demo_mode': True,
            'data_saved': False,
            'message': 'Resultados calculados en memoria. No se guardó ningún dato.'
        })
        
    except Exception as e:
        logger.error(f"❌ TESTPERSONAL: Error calculando resultados: {e}")
        return jsonify({
            'success': False,
            'error': 'Error procesando resultados'
        }), 500

# ============================================================================
# FIN MÓDULO TESTPERSONAL
# ============================================================================

# ============================================================================
# NOTIFICACIONES API
# ============================================================================

@app.route('/api/notifications', methods=['GET'])
@login_required
def api_get_notifications():
    """Obtener notificaciones del usuario actual"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        notifications = Notification.query.filter_by(
            user_id=current_user.id
        ).order_by(
            Notification.created_at.desc()
        ).limit(limit).all()
        
        return jsonify({
            'success': True,
            'notifications': [n.to_dict() for n in notifications],
            'total': len(notifications)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo notificaciones: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo notificaciones'}), 500

@app.route('/api/notifications/unread-count', methods=['GET'])
@login_required
def api_get_unread_count():
    """Obtener contador de notificaciones no leídas"""
    try:
        count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
        
        return jsonify({
            'success': True,
            'count': count
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo contador: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo contador'}), 500

@app.route('/api/notifications/<int:notification_id>/mark-read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Marcar notificación como leída"""
    try:
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user.id
        ).first()
        
        if not notification:
            return jsonify({'error': 'Notificación no encontrada'}), 404
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Notificación marcada como leída'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marcando notificación: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error marcando notificación'}), 500

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def api_mark_all_notifications_read():
    """Marcar todas las notificaciones como leídas"""
    try:
        Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).update({'is_read': True})
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Todas las notificaciones marcadas como leídas'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marcando todas: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error marcando notificaciones'}), 500

# ── COACH NOTIFICATION ENDPOINTS (usa coach_session_required) ──────────────

@app.route('/api/coach/notifications', methods=['GET'])
@coach_session_required
def api_coach_get_notifications():
    """Notificaciones del coach autenticado"""
    try:
        current_coach = getattr(g, 'current_user', None)
        limit = request.args.get('limit', 20, type=int)
        notifications = Notification.query.filter_by(
            user_id=current_coach.id
        ).order_by(Notification.created_at.desc()).limit(limit).all()
        return jsonify({'success': True, 'notifications': [n.to_dict() for n in notifications]}), 200
    except Exception as e:
        logger.error(f"Error obteniendo notificaciones coach: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/notifications/unread-count', methods=['GET'])
@coach_session_required
def api_coach_notifications_unread_count():
    try:
        current_coach = getattr(g, 'current_user', None)
        count = Notification.query.filter_by(user_id=current_coach.id, is_read=False).count()
        return jsonify({'success': True, 'count': count}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/notifications/<int:notification_id>/mark-read', methods=['POST'])
@coach_session_required
def api_coach_mark_notification_read(notification_id):
    try:
        current_coach = getattr(g, 'current_user', None)
        notif = Notification.query.filter_by(id=notification_id, user_id=current_coach.id).first()
        if not notif:
            return jsonify({'error': 'No encontrada'}), 404
        notif.is_read = True
        db.session.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/notifications/mark-all-read', methods=['POST'])
@coach_session_required
def api_coach_mark_all_notifications_read():
    try:
        current_coach = getattr(g, 'current_user', None)
        Notification.query.filter_by(user_id=current_coach.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ────────────────────────────────────────────────────────────────────────────

# Función helper para crear notificaciones
def create_notification(user_id, type, title, message, related_id=None, related_type=None):
    """Helper para crear notificaciones"""
    try:
        notification = Notification(
            user_id=user_id,
            type=type,
            title=title,
            message=message,
            related_id=related_id,
            related_type=related_type
        )
        db.session.add(notification)
        db.session.commit()
        logger.info(f"✅ Notificación creada: {title} para user_id={user_id}")
        return notification
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando notificación: {str(e)}", exc_info=True)
        return None

# ============================================================================
# APIs DE COMUNIDADES DE COACHES
# ============================================================================

@app.route('/api/communities', methods=['POST'])
@coach_required
def api_create_community():
    """Crear una nueva comunidad de coaches"""
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        name = data.get('name', '').strip()
        if not name or len(name) < 3:
            return jsonify({'error': 'El nombre debe tener al menos 3 caracteres'}), 400
        
        if len(name) > 200:
            return jsonify({'error': 'El nombre no puede exceder 200 caracteres'}), 400
        
        description = data.get('description', '').strip()
        if description and len(description) > 1000:
            return jsonify({'error': 'La descripción no puede exceder 1000 caracteres'}), 400
        
        privacy = data.get('privacy', 'private')
        if privacy not in ['private', 'public']:
            return jsonify({'error': 'Privacy debe ser "private" o "public"'}), 400
        
        # Procesar imagen
        image_url = data.get('image_url')
        image_type = data.get('image_type', 'catalog')
        
        if image_type not in ['emoji', 'catalog', 'upload', 'url']:
            image_type = 'catalog'
        
        if image_url:
            image_url = sanitize_string(image_url, 3000)
        
        # Crear comunidad usando SQLAlchemy (funciona con SQLite y PostgreSQL)
        community = CoachCommunity(
            name=sanitize_string(name, 200),
            description=sanitize_string(description, 1000) if description else None,
            image_url=image_url,
            image_type=image_type,
            creator_id=g.current_user.id,
            privacy=privacy,
            is_active=True
        )
        
        db.session.add(community)
        db.session.flush()  # Para obtener el ID antes del commit
        
        # Crear membresía automática del creador como creator
        membership = CommunityMembership(
            community_id=community.id,
            coach_id=g.current_user.id,
            role='creator',
            is_active=True
        )
        
        db.session.add(membership)
        db.session.commit()
        
        logger.info(f"✅ Comunidad creada: {name} (ID: {community.id}) por coach {g.current_user.username}")
        
        # Construir respuesta
        community_dict = {
            'id': community.id,
            'name': community.name,
            'description': community.description,
            'image_url': community.image_url,
            'image_type': community.image_type,
            'creator_id': community.creator_id,
            'privacy': community.privacy,
            'created_at': community.created_at.isoformat() if community.created_at else None,
            'updated_at': community.updated_at.isoformat() if community.updated_at else None,
            'is_active': community.is_active,
            'members_count': 1,
            'my_role': 'creator'
        }
        
        return jsonify({
            'success': True,
            'message': 'Comunidad creada exitosamente',
            'community': community_dict
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando comunidad: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error creando comunidad'}), 500

@app.route('/api/communities', methods=['GET'])
@coach_required
def api_list_communities():
    """Listar comunidades del coach (creadas + donde es miembro)"""
    try:
        # Obtener coach desde la sesión
        coach_id = session.get('coach_user_id')
        coach = User.query.get(coach_id)
        
        if not coach:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        logger.info(f"🔍 COMMUNITIES: Coach {coach.username} (ID: {coach.id}) solicitando comunidades")
        
        # Obtener comunidades donde es miembro activo
        memberships = CommunityMembership.query.filter_by(
            coach_id=coach.id,
            is_active=True
        ).all()
        
        logger.info(f"📊 COMMUNITIES: Encontradas {len(memberships)} membresías para coach {coach.id}")
        
        communities = []
        for membership in memberships:
            # Usar SQLAlchemy para obtener la comunidad
            community = CoachCommunity.query.get(membership.community_id)
            
            if community and community.is_active:
                logger.info(f"   - Comunidad: {community.name} (ID: {community.id}, activa: {community.is_active})")
                
                # Construir dict con TODOS los campos incluyendo image_url/image_type
                community_dict = {
                    'id': community.id,
                    'name': community.name,
                    'description': community.description,
                    'image_url': community.image_url,
                    'image_type': community.image_type or 'catalog',
                    'creator_id': community.creator_id,
                    'created_at': community.created_at.isoformat() if community.created_at else None,
                    'updated_at': community.updated_at.isoformat() if community.updated_at else None,
                    'is_active': community.is_active,
                    'privacy': community.privacy,
                    'my_role': membership.role,
                    'joined_at': membership.joined_at.isoformat() if membership.joined_at else None,
                    'is_creator': (community.creator_id == coach.id),
                    'members_count': CommunityMembership.query.filter_by(
                        community_id=community.id,
                        is_active=True
                    ).count(),
                    'content_count': 0
                }
                communities.append(community_dict)
        
        # Ordenar: primero las creadas por el usuario, luego por fecha de creación
        communities.sort(key=lambda x: (
            0 if x['creator_id'] == coach.id else 1,
            -datetime.fromisoformat(x['created_at']).timestamp() if x['created_at'] else 0
        ))
        
        logger.info(f"✅ COMMUNITIES: Devolviendo {len(communities)} comunidades activas")
        
        return jsonify({
            'success': True,
            'communities': communities,
            'total': len(communities)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listando comunidades: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo comunidades'}), 500

@app.route('/api/communities/<int:community_id>', methods=['GET'])
@coach_required
def api_get_community(community_id):
    """Obtener detalle de una comunidad"""
    try:
        # Usar SQLAlchemy para obtener la comunidad
        community = CoachCommunity.query.get(community_id)
        
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es miembro
        membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=g.current_user.id,
            is_active=True
        ).first()
        
        if not membership:
            return jsonify({'error': 'No eres miembro de esta comunidad'}), 403
        
        # Construir dict con TODOS los campos incluyendo image_url/image_type
        community_dict = {
            'id': community.id,
            'name': community.name,
            'description': community.description,
            'image_url': community.image_url,
            'image_type': community.image_type or 'catalog',
            'creator_id': community.creator_id,
            'created_at': community.created_at.isoformat() if community.created_at else None,
            'updated_at': community.updated_at.isoformat() if community.updated_at else None,
            'is_active': community.is_active,
            'privacy': community.privacy,
            'my_role': membership.role
        }
        
        # Obtener miembros
        members = []
        memberships = CommunityMembership.query.filter_by(
            community_id=community_id,
            is_active=True
        ).all()
        
        for m in memberships:
            coach = m.coach
            members.append({
                'id': m.id,
                'coach_id': coach.id,
                'coach_name': coach.full_name,
                'coach_email': coach.email,
                'coach_avatar': coach.avatar_url,
                'role': m.role,
                'joined_at': m.joined_at.isoformat() if m.joined_at else None
            })
        
        community_dict['members'] = members
        community_dict['members_count'] = len(members)
        
        # NOTA: Content.community_id no existe en producción - no cargar contenido por ahora
        community_dict['recent_content'] = []
        
        return jsonify({
            'success': True,
            'community': community_dict
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo comunidad: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo comunidad'}), 500

@app.route('/api/communities/<int:community_id>', methods=['PUT'])
@coach_required
def api_update_community(community_id):
    """Actualizar información de una comunidad (solo admin)"""
    try:
        # Buscar comunidad usando SQLAlchemy
        community = CoachCommunity.query.get(community_id)
        
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es admin o creator
        membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=g.current_user.id,
            is_active=True
        ).first()
        
        if not membership or (membership.role not in ['admin', 'creator']):
            return jsonify({'error': 'Solo administradores pueden actualizar la comunidad'}), 403
        
        data = request.get_json()
        
        logger.info(f"📥 UPDATE COMMUNITY - Data recibida: {data}")
        
        # Preparar valores de actualización
        name = data.get('name', '').strip() if 'name' in data else None
        description = data.get('description', '').strip() if 'description' in data else None
        privacy = data.get('privacy') if 'privacy' in data else None
        image_url = data.get('image_url', '') if 'image_url' in data else None
        image_type = data.get('image_type', 'catalog') if 'image_type' in data else None
        
        logger.info(f"   image_url extraída: {image_url}")
        logger.info(f"   image_type extraída: {image_type}")
        
        # Validaciones
        if name is not None:
            if not name or len(name) < 3:
                return jsonify({'error': 'El nombre debe tener al menos 3 caracteres'}), 400
            if len(name) > 200:
                return jsonify({'error': 'El nombre no puede exceder 200 caracteres'}), 400
            community.name = sanitize_string(name, 200)
        
        if description is not None:
            if description and len(description) > 1000:
                return jsonify({'error': 'La descripción no puede exceder 1000 caracteres'}), 400
            community.description = sanitize_string(description, 1000) if description else None
        
        if privacy is not None:
            if privacy not in ['private', 'public']:
                return jsonify({'error': 'Privacy debe ser "private" o "public"'}), 400
            community.privacy = privacy
        
        if image_url is not None:
            community.image_url = image_url if image_url else None
        
        if image_type is not None:
            if image_type not in ['emoji', 'catalog', 'upload', 'url']:
                logger.warning(f"   ⚠️ image_type inválido '{image_type}', usando 'catalog'")
                image_type = 'catalog'
            community.image_type = image_type
            logger.info(f"   ✅ image_type guardado: {image_type}")
        
        # Actualizar timestamp
        from datetime import datetime
        community.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"✅ Comunidad actualizada: ID {community_id}, image_type final en DB: {community.image_type}")
        
        # Construir respuesta
        community_dict = {
            'id': community.id,
            'name': community.name,
            'description': community.description,
            'image_url': community.image_url,
            'image_type': community.image_type,
            'creator_id': community.creator_id,
            'created_at': community.created_at.isoformat() if community.created_at else None,
            'updated_at': community.updated_at.isoformat() if community.updated_at else None,
            'is_active': community.is_active,
            'privacy': community.privacy
        }
        
        return jsonify({
            'success': True,
            'message': 'Comunidad actualizada exitosamente',
            'community': community_dict
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando comunidad: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error actualizando comunidad'}), 500

@app.route('/api/communities/<int:community_id>', methods=['DELETE'])
@coach_required
def api_delete_community(community_id):
    """Eliminar una comunidad (solo creador)"""
    try:
        community = CoachCommunity.query.get(community_id)
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es el creador
        if community.creator_id != current_user.id:
            return jsonify({'error': 'Solo el creador puede eliminar la comunidad'}), 403
        
        # Soft delete: marcar como inactiva
        community.is_active = False
        community.updated_at = datetime.utcnow()
        
        # Desactivar todas las membresías
        CommunityMembership.query.filter_by(
            community_id=community_id
        ).update({'is_active': False})
        
        # Desvincular contenido compartido
        Content.query.filter_by(
            community_id=community_id
        ).update({
            'community_id': None,
            'shared_with_community': False
        })
        
        db.session.commit()
        
        logger.info(f"✅ Comunidad eliminada: {community.name} (ID: {community.id})")
        
        return jsonify({
            'success': True,
            'message': 'Comunidad eliminada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error eliminando comunidad: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error eliminando comunidad'}), 500

# ============================================================================
# APIs DE GESTIÓN DE MIEMBROS DE COMUNIDADES
# ============================================================================

@app.route('/api/communities/<int:community_id>/invite', methods=['POST'])
@coach_required
def api_invite_to_community(community_id):
    """Invitar a otro coach a la comunidad por email, WhatsApp o SMS"""
    try:
        community = CoachCommunity.query.get(community_id)
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es admin o moderator
        membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=g.current_user.id,
            is_active=True
        ).first()
        
        if not membership or membership.role not in ['admin', 'moderator']:
            return jsonify({'error': 'Solo administradores y moderadores pueden invitar'}), 403
        
        data = request.get_json()
        
        # Obtener método de invitación
        method = data.get('method', 'email')
        if method not in ['email', 'whatsapp', 'sms']:
            return jsonify({'error': 'Método inválido. Usa: email, whatsapp o sms'}), 400
        
        # Validar nombre
        invitee_name = data.get('invitee_name', '').strip()
        if not invitee_name or len(invitee_name) < 2:
            return jsonify({'error': 'El nombre debe tener al menos 2 caracteres'}), 400
        invitee_name = sanitize_string(invitee_name, 200)
        
        invitee_email = None
        invitee_phone = None
        
        # Validar según método
        if method == 'email':
            valid, result = validate_email(data.get('invitee_email', ''))
            if not valid:
                return jsonify({'error': result}), 400
            invitee_email = result
            
            # Verificar que no sea el mismo usuario
            if invitee_email.lower() == current_user.email.lower():
                return jsonify({'error': 'No puedes invitarte a ti mismo'}), 400
            
            # Verificar si ya existe un coach con ese email
            existing_coach = User.query.filter_by(email=invitee_email, role='coach', active=True).first()
            
            # Si existe, verificar que no sea ya miembro
            if existing_coach:
                existing_membership = CommunityMembership.query.filter_by(
                    community_id=community_id,
                    coach_id=existing_coach.id,
                    is_active=True
                ).first()
                if existing_membership:
                    return jsonify({'error': 'Este coach ya es miembro de la comunidad'}), 400
            
            # Verificar si ya existe una invitación pendiente
            existing_invitation = CommunityInvitation.query.filter_by(
                community_id=community_id,
                invitee_email=invitee_email,
                is_used=False
            ).filter(
                CommunityInvitation.expires_at > datetime.utcnow()
            ).first()
            
            if existing_invitation:
                return jsonify({'error': 'Ya existe una invitación pendiente para este email'}), 400
        
        else:  # whatsapp o sms
            invitee_phone = data.get('invitee_phone', '').strip()
            if not invitee_phone:
                return jsonify({'error': 'El número de teléfono es requerido'}), 400
            
            # Validar formato básico de teléfono
            phone_cleaned = ''.join(filter(str.isdigit, invitee_phone))
            if len(phone_cleaned) < 8:
                return jsonify({'error': 'Número de teléfono inválido'}), 400
            
            invitee_phone = sanitize_string(invitee_phone, 30)
            
            # Verificar si ya existe una invitación pendiente con ese teléfono
            existing_invitation = CommunityInvitation.query.filter_by(
                community_id=community_id,
                invitee_phone=invitee_phone,
                is_used=False
            ).filter(
                CommunityInvitation.expires_at > datetime.utcnow()
            ).first()
            
            if existing_invitation:
                return jsonify({'error': 'Ya existe una invitación pendiente para este número'}), 400
        
        # Crear invitación
        message = data.get('message', '').strip()
        if message:
            message = sanitize_string(message, 500)
        
        token = secrets.token_urlsafe(32)
        invitation = CommunityInvitation(
            community_id=community_id,
            inviter_id=current_user.id,
            invitee_email=invitee_email,
            invitee_phone=invitee_phone,
            invitee_name=invitee_name,
            token=token,
            message=message,
            invitation_method=method,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db.session.add(invitation)
        db.session.commit()
        
        # Enviar invitación según método
        send_result = send_community_invitation(invitation, community, current_user, method)
        
        invitation_link = f"{request.host_url}coach-login?invitation={token}"
        
        logger.info(f"✅ Invitación creada por {method}: {invitee_email or invitee_phone} a comunidad {community.name}")
        
        response_data = {
            'success': True,
            'message': send_result.get('message', 'Invitación enviada'),
            'invitation_link': invitation_link,
            'method': method,
            'invitation': invitation.to_dict()
        }
        
        # Agregar links específicos según método
        if 'whatsapp_link' in send_result:
            response_data['whatsapp_link'] = send_result['whatsapp_link']
        if 'sms_text' in send_result:
            response_data['sms_text'] = send_result['sms_text']
        if 'note' in send_result:
            response_data['note'] = send_result['note']
        
        return jsonify(response_data), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando invitación: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error creando invitación'}), 500

@app.route('/api/extract-og-image', methods=['POST'])
@login_required
def extract_og_image():
    """Extrae la imagen Open Graph de una URL de página web"""
    try:
        import requests
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
        
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL requerida'}), 400
        
        # Validar que sea una URL válida
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return jsonify({'error': 'URL inválida'}), 400
        
        logger.info(f"🔍 Extrayendo imagen Open Graph de: {url}")
        
        # Hacer request a la página con timeout
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"⚠️ Error accediendo a URL: {str(e)}")
            return jsonify({'error': 'No se pudo acceder a la URL'}), 400
        
        # Parsear HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Buscar imagen Open Graph (og:image)
        og_image = soup.find('meta', property='og:image')
        if og_image and og_image.get('content'):
            image_url = og_image['content']
            # Convertir URL relativa a absoluta
            image_url = urljoin(url, image_url)
            logger.info(f"✅ Imagen Open Graph encontrada: {image_url}")
            return jsonify({
                'success': True,
                'image_url': image_url,
                'type': 'og:image'
            }), 200
        
        # Buscar Twitter Card
        twitter_image = soup.find('meta', attrs={'name': 'twitter:image'})
        if twitter_image and twitter_image.get('content'):
            image_url = twitter_image['content']
            image_url = urljoin(url, image_url)
            logger.info(f"✅ Imagen Twitter Card encontrada: {image_url}")
            return jsonify({
                'success': True,
                'image_url': image_url,
                'type': 'twitter:image'
            }), 200
        
        # Buscar link rel="image_src"
        link_image = soup.find('link', rel='image_src')
        if link_image and link_image.get('href'):
            image_url = link_image['href']
            image_url = urljoin(url, image_url)
            logger.info(f"✅ Imagen link rel encontrada: {image_url}")
            return jsonify({
                'success': True,
                'image_url': image_url,
                'type': 'link:image_src'
            }), 200
        
        # Buscar primera imagen grande en el contenido
        images = soup.find_all('img')
        for img in images:
            src = img.get('src') or img.get('data-src')
            if src:
                # Filtrar imágenes muy pequeñas (probablemente iconos)
                width = img.get('width')
                height = img.get('height')
                if width and height:
                    try:
                        if int(width) >= 200 and int(height) >= 200:
                            image_url = urljoin(url, src)
                            logger.info(f"✅ Primera imagen grande encontrada: {image_url}")
                            return jsonify({
                                'success': True,
                                'image_url': image_url,
                                'type': 'first_large_image'
                            }), 200
                    except ValueError:
                        pass
        
        # Si no hay dimensiones, devolver primera imagen
        if images and len(images) > 0:
            src = images[0].get('src') or images[0].get('data-src')
            if src:
                image_url = urljoin(url, src)
                logger.info(f"ℹ️ Primera imagen encontrada: {image_url}")
                return jsonify({
                    'success': True,
                    'image_url': image_url,
                    'type': 'first_image'
                }), 200
        
        logger.warning(f"⚠️ No se encontró ninguna imagen en: {url}")
        return jsonify({'error': 'No se encontró ninguna imagen en la página'}), 404
        
    except ImportError:
        logger.error("❌ beautifulsoup4 no está instalado")
        return jsonify({'error': 'Funcionalidad no disponible - falta dependencia'}), 500
    except Exception as e:
        logger.error(f"❌ Error extrayendo imagen: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error procesando la URL'}), 500

@app.route('/api/my-community-invitations', methods=['GET'])
@coach_required
def api_get_my_community_invitations():
    """Obtener invitaciones pendientes del usuario actual"""
    try:
        # Obtener coach desde la sesión
        coach_id = session.get('coach_user_id')
        coach = User.query.get(coach_id)
        
        if not coach:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        user_email_lower = coach.email.lower()
        logger.info(f"🔍 Buscando invitaciones para: {user_email_lower} (Coach ID: {coach_id}, Username: {coach.username})")
        
        # Buscar invitaciones pendientes para el email del usuario (case-insensitive)
        pending_invitations = CommunityInvitation.query.filter(
            db.func.lower(CommunityInvitation.invitee_email) == user_email_lower,
            CommunityInvitation.is_used == False,
            CommunityInvitation.expires_at > datetime.utcnow()
        ).order_by(CommunityInvitation.created_at.desc()).all()
        
        logger.info(f"📬 Invitaciones encontradas: {len(pending_invitations)}")
        
        invitations_data = []
        for invitation in pending_invitations:
            community = invitation.community
            if community and community.is_active:
                # Verificar que no sea ya miembro
                existing_membership = CommunityMembership.query.filter_by(
                    community_id=community.id,
                    coach_id=coach.id,
                    is_active=True
                ).first()
                
                if not existing_membership:
                    invitations_data.append({
                        'id': invitation.id,
                        'token': invitation.token,
                        'community': {
                            'id': community.id,
                            'name': community.name,
                            'description': community.description
                        },
                        'inviter': {
                            'name': invitation.inviter.full_name if invitation.inviter.full_name else invitation.inviter.username,
                            'username': invitation.inviter.username
                        },
                        'message': invitation.message,
                        'created_at': invitation.created_at.isoformat(),
                        'expires_at': invitation.expires_at.isoformat()
                    })
        
        return jsonify({
            'success': True,
            'invitations': invitations_data,
            'count': len(invitations_data)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo invitaciones: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo invitaciones'}), 500

@app.route('/api/communities/<int:community_id>/members', methods=['GET'])
@coach_required
def api_list_community_members(community_id):
    """Listar miembros de una comunidad"""
    try:
        community = CoachCommunity.query.get(community_id)
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es miembro
        my_membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=g.current_user.id,
            is_active=True
        ).first()
        
        if not my_membership:
            return jsonify({'error': 'No eres miembro de esta comunidad'}), 403
        
        # Obtener miembros activos
        memberships = CommunityMembership.query.filter_by(
            community_id=community_id,
            is_active=True
        ).order_by(CommunityMembership.joined_at.desc()).all()
        
        members = []
        for m in memberships:
            coach = m.coach
            members.append({
                'membership_id': m.id,
                'coach_id': coach.id,
                'coach_name': coach.full_name,
                'coach_email': coach.email,
                'coach_avatar': coach.avatar_url,
                'role': m.role,
                'joined_at': m.joined_at.isoformat() if m.joined_at else None,
                'is_creator': coach.id == community.creator_id
            })
        
        # Ordenar: creador primero, luego admins, luego moderators, luego members
        role_order = {'admin': 0, 'moderator': 1, 'member': 2}
        members.sort(key=lambda x: (
            0 if x['is_creator'] else 1,
            role_order.get(x['role'], 3)
        ))
        
        return jsonify({
            'success': True,
            'members': members,
            'total': len(members),
            'my_role': my_membership.role
        }), 200
        
    except Exception as e:
        logger.error(f"Error listando miembros: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo miembros'}), 500

@app.route('/api/communities/<int:community_id>/members/<int:coach_id>', methods=['DELETE'])
@coach_required
def api_remove_community_member(community_id, coach_id):
    """Remover un miembro de la comunidad"""
    try:
        community = CoachCommunity.query.get(community_id)
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es admin
        my_membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=g.current_user.id,
            is_active=True
        ).first()
        
        if not my_membership or my_membership.role != 'admin':
            return jsonify({'error': 'Solo administradores pueden remover miembros'}), 403
        
        # No puede remover al creador
        if coach_id == community.creator_id:
            return jsonify({'error': 'No puedes remover al creador de la comunidad'}), 400
        
        # No puede removerse a sí mismo (debe salir de la comunidad)
        if coach_id == current_user.id:
            return jsonify({'error': 'No puedes removerte a ti mismo. Usa la opción "Salir de la comunidad"'}), 400
        
        # Obtener membresía a remover
        membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=coach_id,
            is_active=True
        ).first()
        
        if not membership:
            return jsonify({'error': 'El coach no es miembro de esta comunidad'}), 404
        
        # Desactivar membresía
        membership.is_active = False
        db.session.commit()
        
        logger.info(f"✅ Miembro removido: coach {coach_id} de comunidad {community.name}")
        
        return jsonify({
            'success': True,
            'message': 'Miembro removido exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removiendo miembro: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error removiendo miembro'}), 500

@app.route('/api/communities/<int:community_id>/members/<int:coach_id>/role', methods=['PUT'])
@coach_required
def api_change_member_role(community_id, coach_id):
    """Cambiar rol de un miembro (admin puede cambiar a moderator o member)"""
    try:
        community = CoachCommunity.query.get(community_id)
        if not community or not community.is_active:
            return jsonify({'error': 'Comunidad no encontrada'}), 404
        
        # Verificar que el usuario es admin
        my_membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=g.current_user.id,
            is_active=True
        ).first()
        
        if not my_membership or my_membership.role != 'admin':
            return jsonify({'error': 'Solo administradores pueden cambiar roles'}), 403
        
        # No puede cambiar rol del creador
        if coach_id == community.creator_id:
            return jsonify({'error': 'No puedes cambiar el rol del creador'}), 400
        
        data = request.get_json()
        new_role = data.get('role', '').strip().lower()
        
        if new_role not in ['admin', 'moderator', 'member']:
            return jsonify({'error': 'Rol debe ser "admin", "moderator" o "member"'}), 400
        
        # Obtener membresía a actualizar
        membership = CommunityMembership.query.filter_by(
            community_id=community_id,
            coach_id=coach_id,
            is_active=True
        ).first()
        
        if not membership:
            return jsonify({'error': 'El coach no es miembro de esta comunidad'}), 404
        
        old_role = membership.role
        membership.role = new_role
        db.session.commit()
        
        logger.info(f"✅ Rol cambiado: coach {coach_id} de {old_role} a {new_role} en comunidad {community.name}")
        
        return jsonify({
            'success': True,
            'message': f'Rol actualizado a {new_role}',
            'membership': membership.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cambiando rol: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error cambiando rol'}), 500

# ============================================================================
# APIs DE INVITACIONES A COMUNIDADES
# ============================================================================

@app.route('/api/community-invitations/validate/<token>', methods=['GET'])
def api_validate_community_invitation(token):
    """Validar un token de invitación (no requiere autenticación)"""
    try:
        invitation = CommunityInvitation.query.filter_by(token=token).first()
        
        if not invitation:
            return jsonify({'error': 'Invitación no encontrada'}), 404
        
        if not invitation.is_valid():
            reason = 'expirada' if datetime.utcnow() > invitation.expires_at else 'ya utilizada'
            return jsonify({'error': f'Invitación {reason}'}), 400
        
        community = invitation.community
        if not community or not community.is_active:
            return jsonify({'error': 'La comunidad ya no existe'}), 404
        
        inviter = invitation.inviter
        
        return jsonify({
            'success': True,
            'valid': True,
            'invitation': {
                'id': invitation.id,
                'community_name': community.name,
                'community_description': community.description,
                'inviter_name': inviter.full_name,
                'invitee_name': invitation.invitee_name,
                'invitee_email': invitation.invitee_email,
                'message': invitation.message,
                'created_at': invitation.created_at.isoformat() if invitation.created_at else None,
                'expires_at': invitation.expires_at.isoformat() if invitation.expires_at else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error validando invitación: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error validando invitación'}), 500

@app.route('/api/community-invitations/accept/<token>', methods=['POST'])
@coach_required
def api_accept_community_invitation(token):
    """Aceptar una invitación a comunidad (requiere ser coach autenticado)"""
    try:
        # Obtener coach desde la sesión
        coach_id = session.get('coach_user_id')
        coach = User.query.get(coach_id)
        
        if not coach:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        invitation = CommunityInvitation.query.filter_by(token=token).first()
        
        if not invitation:
            return jsonify({'error': 'Invitación no encontrada'}), 404
        
        if not invitation.is_valid():
            reason = 'expirada' if datetime.utcnow() > invitation.expires_at else 'ya utilizada'
            return jsonify({'error': f'Invitación {reason}'}), 400
        
        community = invitation.community
        if not community or not community.is_active:
            return jsonify({'error': 'La comunidad ya no existe'}), 404
        
        # Verificar que el email coincide con el usuario actual (case-insensitive)
        if invitation.invitee_email.lower() != coach.email.lower():
            logger.warning(f"⚠️ Email mismatch: invitation={invitation.invitee_email}, coach={coach.email}")
            return jsonify({'error': 'Esta invitación no corresponde a tu email'}), 403
        
        # Verificar que no sea ya miembro
        existing_membership = CommunityMembership.query.filter_by(
            community_id=community.id,
            coach_id=coach.id,
            is_active=True
        ).first()
        
        if existing_membership:
            return jsonify({'error': 'Ya eres miembro de esta comunidad'}), 400
        
        # Crear membresía
        membership = CommunityMembership(
            community_id=community.id,
            coach_id=coach.id,
            role='member'
        )
        db.session.add(membership)
        
        # Marcar invitación como usada
        invitation.mark_as_used(coach.id)
        
        db.session.commit()
        
        logger.info(f"✅ Invitación aceptada: coach {coach.username} unido a comunidad {community.name}")
        
        return jsonify({
            'success': True,
            'message': f'Te has unido exitosamente a {community.name}',
            'community': community.to_dict(),
            'membership': membership.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error aceptando invitación: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error aceptando invitación'}), 500

@app.route('/api/community-invitations/reject/<token>', methods=['POST'])
def api_reject_community_invitation(token):
    """Rechazar una invitación a comunidad (no requiere autenticación)"""
    try:
        invitation = CommunityInvitation.query.filter_by(token=token).first()
        
        if not invitation:
            return jsonify({'error': 'Invitación no encontrada'}), 404
        
        if not invitation.is_valid():
            return jsonify({'error': 'La invitación ya no es válida'}), 400
        
        # Marcar como usada (rechazada)
        invitation.mark_as_used()
        db.session.commit()
        
        logger.info(f"ℹ️ Invitación rechazada: {invitation.invitee_email}")
        
        return jsonify({
            'success': True,
            'message': 'Invitación rechazada'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error rechazando invitación: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error rechazando invitación'}), 500

# ============================================================================
# SISTEMA DE GAMIFICACIÓN - ETAPA 2: API BÁSICA
# ============================================================================

# --- Helper Functions para Gamificación ---

def get_coachee_points(coachee_id):
    """Obtiene los puntos y nivel actual de un coachee"""
    try:
        from sqlalchemy import text
        result = db.session.execute(
            text("SELECT total_points, current_level FROM coachee_points WHERE coachee_id = :coachee_id"),
            {'coachee_id': coachee_id}
        )
        row = result.fetchone()
        
        if row:
            return {
                'total_points': row[0],
                'current_level': row[1]
            }
        else:
            # Si no existe, crear registro inicial
            db.session.execute(
                text("INSERT INTO coachee_points (coachee_id, total_points, current_level, created_at, updated_at) VALUES (:id, 0, 1, datetime('now'), datetime('now'))"),
                {'id': coachee_id}
            )
            db.session.commit()
            return {
                'total_points': 0,
                'current_level': 1
            }
    except Exception as e:
        logger.error(f"Error obteniendo puntos del coachee {coachee_id}: {e}")
        return {
            'total_points': 0,
            'current_level': 1
        }

def get_level_info(level_number):
    """Obtiene información de un nivel específico"""
    try:
        from sqlalchemy import text
        result = db.session.execute(
            text("SELECT level_name, points_required, icon_class, color_hex, description, unlock_message FROM levels_system WHERE level_number = :level"),
            {'level': level_number}
        )
        row = result.fetchone()
        
        if row:
            return {
                'level_number': level_number,
                'level_name': row[0],
                'points_required': row[1],
                'icon_class': row[2],
                'color_hex': row[3],
                'description': row[4],
                'unlock_message': row[5]
            }
        else:
            return None
    except Exception as e:
        logger.error(f"Error obteniendo info del nivel {level_number}: {e}")
        return None

def get_next_level_info(current_level):
    """Obtiene información del siguiente nivel"""
    return get_level_info(current_level + 1)

# --- API Endpoints de Gamificación ---

@app.route('/api/coachee/points/summary', methods=['GET'])
def get_coachee_points_summary():
    """
    Obtiene resumen de puntos y nivel del coachee actual (SOLO LECTURA)
    Retorna: {success, data: {total_points, current_level, level_name, points_to_next, progress, next_level_info}}
    """
    # DEBUG: Ver qué cookies llegaron
    logger.info(f"🍪 GAMIFICACIÓN: Cookies recibidas: {request.cookies.keys()}")
    logger.info(f"🔐 GAMIFICACIÓN: Session data: {dict(session)}")
    
    # Verificar que es coachee (compatibilidad con ambos nombres de variable)
    coachee_id = session.get('coachee_id') or session.get('coachee_user_id')
    
    if not coachee_id:
        logger.warning("⚠️ GAMIFICACIÓN: Intento de acceso sin sesión de coachee")
        return jsonify({'success': False, 'error': 'No autorizado - sesión de coachee requerida'}), 401
    
    try:
        logger.info(f"🎮 GAMIFICACIÓN: Coachee {coachee_id} solicita resumen de puntos")
        
        # Obtener puntos actuales
        points_data = get_coachee_points(coachee_id)
        
        # Obtener info del nivel actual
        current_level_info = get_level_info(points_data['current_level'])
        
        # Obtener info del siguiente nivel
        next_level_info = get_next_level_info(points_data['current_level'])
        
        # Calcular progreso
        if next_level_info:
            current_level_base = current_level_info['points_required'] if current_level_info else 0
            next_level_points = next_level_info['points_required']
            points_for_next = next_level_points - current_level_base
            current_progress = points_data['total_points'] - current_level_base
            progress_percentage = int((current_progress / points_for_next) * 100) if points_for_next > 0 else 0
            points_to_next = next_level_points - points_data['total_points']
        else:
            # Nivel máximo alcanzado
            progress_percentage = 100
            points_to_next = 0
        
        response = {
            'success': True,
            'data': {
                'total_points': points_data['total_points'],
                'current_level': points_data['current_level'],
                'level_name': current_level_info['level_name'] if current_level_info else 'Novato',
                'level_icon': current_level_info['icon_class'] if current_level_info else 'fa-seedling',
                'level_color': current_level_info['color_hex'] if current_level_info else '#10b981',
                'points_to_next': points_to_next,
                'progress': progress_percentage,
                'next_level_name': next_level_info['level_name'] if next_level_info else 'Máximo',
                'is_max_level': next_level_info is None
            }
        }
        
        # Agregar estadísticas de tareas completadas
        try:
            completed_tasks_count = db.session.execute(
                text("""
                    SELECT COUNT(DISTINCT t.id)
                    FROM task t
                    JOIN task_progress tp ON tp.task_id = t.id
                    WHERE t.coachee_id = :coachee_id
                    AND t.is_active = true
                    AND tp.status = 'completed'
                """),
                {'coachee_id': coachee_id}
            ).scalar()
            
            response['data']['completed_tasks'] = completed_tasks_count or 0
            logger.info(f"📊 GAMIFICACIÓN: Coachee {coachee_id} - {completed_tasks_count} tareas completadas")
        except Exception as task_error:
            logger.warning(f"⚠️ No se pudieron obtener tareas completadas: {str(task_error)}")
            response['data']['completed_tasks'] = 0
        
        logger.info(f"✅ GAMIFICACIÓN: Coachee {coachee_id} - {points_data['total_points']} pts, Nivel {points_data['current_level']}")
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"❌ GAMIFICACIÓN: Error en get_coachee_points_summary: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error obteniendo puntos'}), 500

# ============================================================================
# ENDPOINTS: Contratos de Suscripción
# ============================================================================

CONTRACTS_FOLDER = 'uploads/contracts'

def ensure_contracts_folder():
    if not os.path.exists(CONTRACTS_FOLDER):
        os.makedirs(CONTRACTS_FOLDER)

ALLOWED_CONTRACT_EXTENSIONS = {'pdf', 'doc', 'docx'}

def allowed_contract_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_CONTRACT_EXTENSIONS


@app.route('/api/coach/contracts', methods=['GET'])
@login_required
def get_contracts():
    """Listar contratos enviados por el coach"""
    try:
        current_coach = User.query.get(current_user.id)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        contracts = SubscriptionContract.query.filter_by(coach_id=current_coach.id)\
            .order_by(SubscriptionContract.created_at.desc()).all()

        result = []
        for c in contracts:
            coachee = User.query.get(c.coachee_id)
            result.append({
                'id': c.id,
                'coachee_id': c.coachee_id,
                'coachee_name': coachee.full_name or coachee.username if coachee else '—',
                'filename': c.filename,
                'num_sessions': c.num_sessions,
                'summary': c.summary,
                'status': c.status,
                'sent_at': c.sent_at.isoformat() if c.sent_at else None,
                'signed_at': c.signed_at.isoformat() if c.signed_at else None,
                'created_at': c.created_at.isoformat() if c.created_at else None,
            })
        return jsonify({'success': True, 'contracts': result})

    except Exception as e:
        logger.error(f"❌ CONTRACTS GET: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error obteniendo contratos'}), 500


@app.route('/api/coach/contracts/upload', methods=['POST'])
@login_required
def upload_contract():
    """Subir archivo de contrato y crear registro"""
    try:
        current_coach = User.query.get(current_user.id)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        if 'contract_file' not in request.files:
            return jsonify({'success': False, 'error': 'No se recibió ningún archivo'}), 400

        file = request.files['contract_file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Nombre de archivo vacío'}), 400

        if not allowed_contract_file(file.filename):
            return jsonify({'success': False, 'error': 'Formato no permitido. Usa PDF, DOC o DOCX'}), 400

        coachee_id = request.form.get('coachee_id')
        num_sessions = request.form.get('num_sessions')
        summary = request.form.get('summary', '')

        if not coachee_id:
            return jsonify({'success': False, 'error': 'Debes seleccionar un coachee'}), 400

        coachee = User.query.filter_by(id=int(coachee_id), coach_id=current_coach.id, role='coachee').first()
        if not coachee:
            return jsonify({'success': False, 'error': 'Coachee no encontrado'}), 404

        ensure_contracts_folder()
        original_name = secure_filename(file.filename)
        unique_filename = f"contract_{current_coach.id}_{coachee_id}_{secrets.token_hex(8)}_{original_name}"
        file_path = os.path.join(CONTRACTS_FOLDER, unique_filename)
        file.save(file_path)

        contract = SubscriptionContract(
            coach_id=current_coach.id,
            coachee_id=int(coachee_id),
            filename=original_name,
            file_path=file_path,
            num_sessions=int(num_sessions) if num_sessions else None,
            summary=summary,
            status='pending',
        )
        db.session.add(contract)
        db.session.commit()

        return jsonify({'success': True, 'contract_id': contract.id, 'message': 'Contrato subido correctamente'})

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ CONTRACTS UPLOAD: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error subiendo contrato'}), 500


@app.route('/api/coach/contracts/<int:contract_id>/send', methods=['POST'])
@login_required
def send_contract(contract_id):
    """Enviar invitación de suscripción al coachee (email + notificación interna)"""
    try:
        current_coach = User.query.get(current_user.id)
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        contract = SubscriptionContract.query.filter_by(id=contract_id, coach_id=current_coach.id).first()
        if not contract:
            return jsonify({'success': False, 'error': 'Contrato no encontrado'}), 404

        coachee = User.query.get(contract.coachee_id)
        if not coachee:
            return jsonify({'success': False, 'error': 'Coachee no encontrado'}), 404

        sessions_text = f'{contract.num_sessions} sesiones' if contract.num_sessions else 'sesiones según acuerdo'
        coach_name = current_coach.full_name or current_coach.username
        coachee_name = coachee.full_name or coachee.username

        # 1. Notificación interna
        notification = Notification(
            user_id=coachee.id,
            type='subscription_contract',
            title='Tienes un contrato de coaching pendiente',
            message=f'{coach_name} te ha enviado un contrato de coaching ({sessions_text}). '
                    f'Ingresa a la plataforma para leerlo, firmarlo y elegir tu medio de pago.',
            related_id=contract.id,
            related_type='subscription_contract',
            is_read=False,
        )
        db.session.add(notification)

        contract.status = 'pending'
        contract.sent_at = datetime.utcnow()
        db.session.commit()

        # 2. Email
        email_sent = False
        try:
            smtp_server = os.environ.get('SMTP_SERVER')
            smtp_port = int(os.environ.get('SMTP_PORT', '587'))
            smtp_username = os.environ.get('SMTP_USERNAME')
            smtp_password = os.environ.get('SMTP_PASSWORD')

            if all([smtp_server, smtp_username, smtp_password]):
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                platform_url = request.url_root.rstrip('/')
                summary_html = f'<p style="background:#f0f4ff;padding:1rem;border-left:4px solid #6366f1;border-radius:4px;">{contract.summary}</p>' if contract.summary else ''

                html_body = f"""
                <html><body style="font-family:Arial,sans-serif;color:#333;line-height:1.6;">
                <div style="max-width:620px;margin:0 auto;padding:24px;background:#f9fafb;border-radius:12px;">
                    <h2 style="color:#6366f1;margin-bottom:0.5rem;">Tu contrato de coaching está listo</h2>
                    <p>Hola <strong>{coachee_name}</strong>,</p>
                    <p><strong>{coach_name}</strong> te ha enviado un contrato de coaching por <strong>{sessions_text}</strong>.</p>
                    {summary_html}
                    <h3 style="color:#111827;margin-top:1.5rem;">Pasos a completar:</h3>
                    <ol style="padding-left:1.2rem;">
                        <li style="margin-bottom:0.5rem;"><strong>Leer el contrato</strong> — Revisa todos los términos y condiciones.</li>
                        <li style="margin-bottom:0.5rem;"><strong>Firmar el contrato</strong> — Confirma tu aceptación desde la plataforma.</li>
                        <li style="margin-bottom:0.5rem;"><strong>Elegir medio de pago</strong> — Selecciona cómo deseas pagar tu plan de coaching.</li>
                    </ol>
                    <div style="text-align:center;margin:2rem 0;">
                        <a href="{platform_url}/coachee-dashboard"
                           style="background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;padding:14px 32px;text-decoration:none;border-radius:8px;display:inline-block;font-weight:bold;font-size:1rem;">
                            Ver mi contrato
                        </a>
                    </div>
                    <hr style="border:none;border-top:1px solid #e5e7eb;margin:1.5rem 0;">
                    <p style="color:#9ca3af;font-size:0.82rem;">InstaCoach · Este mensaje fue generado automáticamente.</p>
                </div>
                </body></html>
                """

                msg = MIMEMultipart('alternative')
                msg['From'] = smtp_username
                msg['To'] = coachee.email
                msg['Subject'] = f'📄 Tu contrato de coaching — {sessions_text}'
                msg.attach(MIMEText(html_body, 'html'))

                server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
                server.quit()
                email_sent = True
                logger.info(f"✅ CONTRACTS: Email enviado a {coachee.email}")
        except Exception as email_err:
            logger.warning(f"⚠️ CONTRACTS: Email no enviado: {email_err}")

        return jsonify({
            'success': True,
            'message': 'Invitación enviada correctamente',
            'email_sent': email_sent,
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ CONTRACTS SEND: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error enviando contrato'}), 500


@app.route('/uploads/contracts/<path:filename>')
@login_required
def serve_contract_file(filename):
    """Servir archivo de contrato"""
    return send_from_directory(os.path.abspath(CONTRACTS_FOLDER), filename)


@app.route('/api/coachee/contracts', methods=['GET'])
@login_required
def get_coachee_contracts():
    """Contratos pendientes del coachee"""
    try:
        contracts = SubscriptionContract.query.filter_by(coachee_id=current_user.id)\
            .order_by(SubscriptionContract.created_at.desc()).all()
        result = []
        for c in contracts:
            coach = User.query.get(c.coach_id)
            result.append({
                'id': c.id,
                'coach_name': coach.full_name or coach.username if coach else '—',
                'filename': c.filename,
                'file_url': f'/uploads/contracts/{os.path.basename(c.file_path)}',
                'num_sessions': c.num_sessions,
                'summary': c.summary,
                'status': c.status,
                'sent_at': c.sent_at.isoformat() if c.sent_at else None,
                'signed_at': c.signed_at.isoformat() if c.signed_at else None,
            })
        return jsonify({'success': True, 'contracts': result})
    except Exception as e:
        logger.error(f"❌ COACHEE CONTRACTS GET: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error obteniendo contratos'}), 500


@app.route('/api/coachee/contracts/<int:contract_id>/sign', methods=['POST'])
@login_required
def sign_contract(contract_id):
    """Coachee firma el contrato"""
    try:
        contract = SubscriptionContract.query.filter_by(id=contract_id, coachee_id=current_user.id).first()
        if not contract:
            return jsonify({'success': False, 'error': 'Contrato no encontrado'}), 404
        contract.status = 'signed'
        contract.signed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Contrato firmado correctamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# ENDPOINTS: Registros de Sesiones de Coaching
# ============================================================================

@app.route('/api/coach/session-records', methods=['GET'])
@coach_required
def get_session_records():
    """Listar todas las sesiones de coaching del coach actual"""
    try:
        current_coach = User.query.get(session['coach_user_id'])
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        records = SessionRecord.query.filter_by(coach_id=current_coach.id)\
            .order_by(SessionRecord.session_number.asc()).all()

        result = []
        for r in records:
            participants_ids = json.loads(r.participants) if r.participants else []
            participants_info = []
            for pid in participants_ids:
                u = User.query.get(pid)
                if u:
                    participants_info.append({'id': u.id, 'name': u.username, 'email': u.email})

            commitments = json.loads(r.commitments) if r.commitments else []

            result.append({
                'id': r.id,
                'session_number': r.session_number,
                'name': r.name,
                'objective': r.objective,
                'participants': participants_info,
                'content': r.content,
                'commitments': commitments,
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'updated_at': r.updated_at.isoformat() if r.updated_at else None,
            })

        return jsonify({'success': True, 'sessions': result})

    except Exception as e:
        logger.error(f"❌ SESSION-RECORDS GET: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error obteniendo sesiones'}), 500


@app.route('/api/coach/session-records', methods=['POST'])
@coach_required
def create_session_record():
    """Crear una nueva sesión de coaching"""
    try:
        current_coach = User.query.get(session['coach_user_id'])
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        # Determinar el número de sesión siguiente
        last = SessionRecord.query.filter_by(coach_id=current_coach.id)\
            .order_by(SessionRecord.session_number.desc()).first()
        next_number = 0 if last is None else last.session_number + 1
        auto_name = 'Sesión Cero' if next_number == 0 else f'Sesión {next_number}'

        data = request.get_json() or {}
        participants = data.get('participants', [])
        commitments = data.get('commitments', [])

        record = SessionRecord(
            coach_id=current_coach.id,
            session_number=next_number,
            name=data.get('name', auto_name),
            objective=data.get('objective', ''),
            participants=json.dumps(participants),
            content=data.get('content', ''),
            commitments=json.dumps(commitments),
        )
        db.session.add(record)
        db.session.commit()

        return jsonify({'success': True, 'session': {
            'id': record.id,
            'session_number': record.session_number,
            'name': record.name,
            'auto_name': auto_name,
        }}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ SESSION-RECORDS CREATE: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error creando sesión'}), 500


@app.route('/api/coach/session-records/<int:session_id>', methods=['GET'])
@coach_required
def get_session_record(session_id):
    """Obtener detalle de una sesión"""
    try:
        current_coach = User.query.get(session['coach_user_id'])
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        r = SessionRecord.query.filter_by(id=session_id, coach_id=current_coach.id).first()
        if not r:
            return jsonify({'success': False, 'error': 'Sesión no encontrada'}), 404

        participants_ids = json.loads(r.participants) if r.participants else []
        participants_info = []
        for pid in participants_ids:
            u = User.query.get(pid)
            if u:
                participants_info.append({'id': u.id, 'name': u.username, 'email': u.email})

        commitments = json.loads(r.commitments) if r.commitments else []

        return jsonify({'success': True, 'session': {
            'id': r.id,
            'session_number': r.session_number,
            'name': r.name,
            'objective': r.objective,
            'participants': participants_info,
            'content': r.content,
            'commitments': commitments,
            'created_at': r.created_at.isoformat() if r.created_at else None,
            'updated_at': r.updated_at.isoformat() if r.updated_at else None,
        }})

    except Exception as e:
        logger.error(f"❌ SESSION-RECORDS GET ONE: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error obteniendo sesión'}), 500


@app.route('/api/coach/session-records/<int:session_id>', methods=['PUT'])
@coach_required
def update_session_record(session_id):
    """Guardar/actualizar una sesión de coaching"""
    try:
        current_coach = User.query.get(session['coach_user_id'])
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        r = SessionRecord.query.filter_by(id=session_id, coach_id=current_coach.id).first()
        if not r:
            return jsonify({'success': False, 'error': 'Sesión no encontrada'}), 404

        data = request.get_json() or {}
        if 'name' in data:
            r.name = data['name']
        if 'objective' in data:
            r.objective = data['objective']
        if 'participants' in data:
            r.participants = json.dumps(data['participants'])
        if 'content' in data:
            r.content = data['content']
        if 'commitments' in data:
            r.commitments = json.dumps(data['commitments'])
        r.updated_at = datetime.utcnow()

        db.session.commit()
        return jsonify({'success': True, 'message': 'Sesión guardada correctamente'})

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ SESSION-RECORDS UPDATE: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Error guardando sesión'}), 500


@app.route('/api/coach/session-records/next-name', methods=['GET'])
@coach_required
def get_next_session_name():
    """Retorna el nombre automático para la próxima sesión"""
    try:
        current_coach = User.query.get(session['coach_user_id'])
        if not current_coach or current_coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        last = SessionRecord.query.filter_by(coach_id=current_coach.id)\
            .order_by(SessionRecord.session_number.desc()).first()
        next_number = 0 if last is None else last.session_number + 1
        auto_name = 'Sesión Cero' if next_number == 0 else f'Sesión {next_number}'

        return jsonify({'success': True, 'next_number': next_number, 'auto_name': auto_name})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# API: Acuerdos de Compromiso de Coaching
# ============================================================================

@app.route('/api/coach/profile', methods=['GET'])
@coach_required
def api_coach_profile():
    """Retorna los datos de perfil del coach actual para auto-rellenar formularios"""
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403
        return jsonify({
            'success': True,
            'profile': {
                'id': coach.id,
                'full_name': coach.full_name or coach.username,
                'email': coach.email,
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/coach/agreements', methods=['GET'])
@coach_required
def list_agreements():
    """Lista los acuerdos de compromiso del coach"""
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        agreements = CoachingAgreement.query.filter_by(coach_id=coach.id)\
            .order_by(CoachingAgreement.updated_at.desc()).all()

        result = []
        for ag in agreements:
            data = {}
            if ag.contract_data:
                try:
                    data = json.loads(ag.contract_data)
                except Exception:
                    pass
            coachee_name = ''
            if ag.coachee_id:
                coachee = User.query.get(ag.coachee_id)
                if coachee:
                    coachee_name = coachee.full_name or coachee.username
            result.append({
                'id': ag.id,
                'status': ag.status,
                'coachee_id': ag.coachee_id,
                'coachee_name': coachee_name or data.get('cliente_nombre', ''),
                'contract_data': data,
                'created_at': ag.created_at.isoformat() if ag.created_at else None,
                'updated_at': ag.updated_at.isoformat() if ag.updated_at else None,
            })

        return jsonify({'success': True, 'agreements': result})
    except Exception as e:
        logger.error(f'Error listing agreements: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/coach/agreements', methods=['POST'])
@coach_required
def create_agreement():
    """Crea o actualiza un acuerdo de compromiso"""
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        payload = request.get_json(force=True) or {}
        coachee_id = payload.get('coachee_id') or None
        status = payload.get('status', 'borrador')
        contract_data = payload.get('contract_data', {})

        ag = CoachingAgreement(
            coach_id=coach.id,
            coachee_id=int(coachee_id) if coachee_id else None,
            status=status,
            contract_data=json.dumps(contract_data, ensure_ascii=False),
        )
        db.session.add(ag)
        db.session.commit()

        return jsonify({'success': True, 'id': ag.id, 'message': 'Acuerdo guardado'})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error creating agreement: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/coach/agreements/<int:ag_id>', methods=['PUT'])
@coach_required
def update_agreement(ag_id):
    """Actualiza un acuerdo existente"""
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        ag = CoachingAgreement.query.filter_by(id=ag_id, coach_id=coach.id).first()
        if not ag:
            return jsonify({'success': False, 'error': 'Acuerdo no encontrado'}), 404

        payload = request.get_json(force=True) or {}
        if 'coachee_id' in payload:
            ag.coachee_id = int(payload['coachee_id']) if payload['coachee_id'] else None
        if 'status' in payload:
            ag.status = payload['status']
        if 'contract_data' in payload:
            ag.contract_data = json.dumps(payload['contract_data'], ensure_ascii=False)
        ag.updated_at = datetime.utcnow()

        db.session.commit()
        return jsonify({'success': True, 'message': 'Acuerdo actualizado'})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error updating agreement: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/coach/agreements/<int:ag_id>', methods=['DELETE'])
@coach_required
def delete_agreement(ag_id):
    """Elimina un acuerdo"""
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        ag = CoachingAgreement.query.filter_by(id=ag_id, coach_id=coach.id).first()
        if not ag:
            return jsonify({'success': False, 'error': 'Acuerdo no encontrado'}), 404

        db.session.delete(ag)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Acuerdo eliminado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/coach/agreements/<int:ag_id>/status', methods=['PATCH'])
@coach_required
def patch_agreement_status(ag_id):
    """Actualiza solo el estado de un acuerdo"""
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        ag = CoachingAgreement.query.filter_by(id=ag_id, coach_id=coach.id).first()
        if not ag:
            return jsonify({'success': False, 'error': 'Acuerdo no encontrado'}), 404

        payload = request.get_json(force=True) or {}
        new_status = payload.get('status')
        if new_status not in ('borrador', 'enviado', 'firmado'):
            return jsonify({'success': False, 'error': 'Estado inválido'}), 400

        ag.status = new_status
        ag.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'status': ag.status})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# FIN API Acuerdos de Compromiso
# ============================================================================

# ============================================================================
# API: Estadísticas de Comportamiento por Sesión
# ============================================================================

@app.route('/api/coach/session-stats', methods=['GET'])
@coach_required
def get_session_stats():
    """
    Retorna estadísticas de comportamiento del coachee por sesión.
    Parsea el campo 'comportamiento' dentro del JSON de 'content' de cada session_record.
    Opcionalmente filtra por coachee_id.
    """
    try:
        coach = User.query.get(session['coach_user_id'])
        if not coach or coach.role != 'coach':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403

        filter_coachee_id = request.args.get('coachee_id', type=int)

        # Sesiones regulares (session_number > 0) del coach
        query = SessionRecord.query.filter_by(coach_id=coach.id)\
            .filter(SessionRecord.session_number > 0)\
            .order_by(SessionRecord.session_number.asc())
        sessions = query.all()

        # Obtener todos los coachees del coach para mapear nombres
        coachees_map = {}
        for c in User.query.filter_by(coach_id=coach.id, role='coachee').all():
            coachees_map[c.id] = c.full_name or c.username

        stats_by_coachee = {}

        for ses in sessions:
            # Parsear participants para obtener IDs de coachees
            participants = []
            try:
                raw = json.loads(ses.participants or '[]')
                if isinstance(raw, list):
                    participants = [int(x) for x in raw if x]
            except Exception:
                pass

            if not participants:
                continue

            # Parsear content para obtener comportamiento
            content = {}
            try:
                content = json.loads(ses.content or '{}')
            except Exception:
                pass

            comp = content.get('comportamiento', {}) if isinstance(content, dict) else {}

            ses_data = {
                'session_number': ses.session_number,
                'name': ses.name,
                'created_at': ses.created_at.strftime('%Y-%m-%d') if ses.created_at else '',
                'asistio':      comp.get('asistio'),
                'puntual':      comp.get('puntual'),
                'completo':     comp.get('completo'),
                'compromisos':  comp.get('compromisos'),
                'tareas':       comp.get('tareas'),
                'preparado':    comp.get('preparado'),
                'disposicion':  comp.get('disposicion'),
                'situacion':    comp.get('situacion'),
            }

            for cid in participants:
                if filter_coachee_id and cid != filter_coachee_id:
                    continue
                if cid not in stats_by_coachee:
                    stats_by_coachee[cid] = {
                        'coachee_id': cid,
                        'coachee_name': coachees_map.get(cid, f'Coachee {cid}'),
                        'total_sesiones': 0,
                        'asistio_si': 0,
                        'puntual_si': 0,
                        'completo_si': 0,
                        'compromisos_si': 0,
                        'total_con_compromisos': 0,
                        'tareas_si': 0,
                        'total_con_tareas': 0,
                        'preparado_si': 0,
                        'disposicion_si': 0,
                        'situacion_si': 0,
                        'sesiones': [],
                    }

                s = stats_by_coachee[cid]
                s['total_sesiones'] += 1
                if comp.get('asistio') == 'si':   s['asistio_si'] += 1
                if comp.get('puntual') == 'si':    s['puntual_si'] += 1
                if comp.get('completo') == 'si':   s['completo_si'] += 1
                if comp.get('compromisos') is not None:
                    s['total_con_compromisos'] += 1
                    if comp.get('compromisos') == 'si': s['compromisos_si'] += 1
                if comp.get('tareas') is not None:
                    s['total_con_tareas'] += 1
                    if comp.get('tareas') == 'si': s['tareas_si'] += 1
                if comp.get('preparado') == 'si':  s['preparado_si'] += 1
                if comp.get('disposicion') == 'si': s['disposicion_si'] += 1
                if comp.get('situacion') == 'si':  s['situacion_si'] += 1
                s['sesiones'].append(ses_data)

        # Calcular porcentajes
        def pct(val, total):
            return round((val / total) * 100) if total > 0 else None

        for cid, s in stats_by_coachee.items():
            t = s['total_sesiones']
            s['pct_asistencia']   = pct(s['asistio_si'], t)
            s['pct_puntualidad']  = pct(s['puntual_si'], t)
            s['pct_completo']     = pct(s['completo_si'], t)
            s['pct_compromisos']  = pct(s['compromisos_si'], s['total_con_compromisos'])
            s['pct_tareas']       = pct(s['tareas_si'], s['total_con_tareas'])
            s['pct_preparado']    = pct(s['preparado_si'], t)
            s['pct_disposicion']  = pct(s['disposicion_si'], t)
            s['pct_situacion']    = pct(s['situacion_si'], t)

        return jsonify({
            'success': True,
            'stats_by_coachee': stats_by_coachee,
        })

    except Exception as e:
        logger.error(f'Error en session-stats: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# FIN API Estadísticas de Comportamiento
# ============================================================================

# ============================================================================
# INICIALIZACIÓN DE LA APP
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        auto_initialize_database()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5002)), debug=False, use_reloader=False)

