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
        }), 500

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
        
        # Verificar que el usuario admin existe
        with app.app_context():
            admin_user = User.query.filter_by(username='admin').first()
            user_count = User.query.count()
            
        return jsonify({
            'status': 'success',
            'message': 'Base de datos verificada/inicializada correctamente',
            'admin_exists': admin_user is not None,
            'user_count': user_count,
            'initialization_result': result,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
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
        with app.app_context():
            db.create_all()
            
            # Crear usuarios por defecto del sistema
            create_default_users()
            
            # Verificar si ya existe la evaluación de asertividad
            assessment = Assessment.query.first()
            if not assessment:
                print("🔄 Inicializando evaluación de asertividad...")
                
                # Crear evaluación de asertividad
                assessment = Assessment(
                    title='Evaluación de Asertividad',
                    description='Evaluación para medir el nivel de asertividad en diferentes situaciones'
                )
                db.session.add(assessment)
                db.session.commit()
                
                # Preguntas de asertividad en español
                questions_data = [
                    {
                        "content": "Cuando alguien critica tu trabajo de manera injusta, ¿cómo sueles responder?",
                        "options": [
                            "Permanezco en silencio para evitar el conflicto",
                            "Me defiendo con calma y hechos",
                            "Me enojo y me pongo a la defensiva",
                            "Intento cambiar de tema"
                        ]
                    },
                    {
                        "content": "Si un amigo te pide dinero repetidamente y no lo devuelve, ¿abordarías este tema?",
                        "options": [
                            "No, evitaría mencionarlo",
                            "Sí, tendría una conversación honesta al respecto",
                            "Dejaría de prestar pero no lo hablaría",
                            "Pondría excusas para no prestar más"
                        ]
                    },
                    {
                        "content": "¿Con qué frecuencia expresas tu opinión en discusiones grupales?",
                        "options": [
                            "Rara vez - Suelo estar de acuerdo con la mayoría",
                            "A menudo - Cuando el tema me importa mucho",
                            "Siempre - Hablo sin importar la opinión de los demás",
                            "A veces - Solo cuando me siento muy seguro"
                        ]
                    },
                    {
                        "content": "Cuando alguien se cuela delante de ti en una fila, ¿qué sueles hacer?",
                        "options": [
                            "Dejo que se cuelen y evito el conflicto",
                            "Señalo educadamente que hay una fila",
                            "Los confronto agresivamente",
                            "No digo nada pero me frustro"
                        ]
                    },
                    {
                        "content": "¿Cómo manejas las solicitudes que no quieres cumplir?",
                        "options": [
                            "Digo que sí aunque no quiera",
                            "Digo que no de forma clara y directa",
                            "Evito a la persona o la situación",
                            "Pongo excusas"
                        ]
                    },
                    {
                        "content": "Si tu comida en un restaurante no está preparada como la pediste, ¿qué harías?",
                        "options": [
                            "No digo nada pero dejo poca propina",
                            "Expreso mis inquietudes educadamente al camarero",
                            "Me quejo en voz alta y exijo ver al gerente",
                            "Nunca vuelvo al restaurante"
                        ]
                    },
                    {
                        "content": "¿Cómo sueles reaccionar ante los cumplidos?",
                        "options": [
                            "Los minimizo o desvío",
                            "Acepto los cumplidos con gratitud",
                            "Me siento muy incómodo",
                            "Los rechazo completamente"
                        ]
                    },
                    {
                        "content": "Durante una reunión de equipo, ¿cómo respondes cuando no estás de acuerdo con una idea propuesta?",
                        "options": [
                            "Me quedo callado y acepto",
                            "Expreso mi desacuerdo respetuosamente y propongo alternativas",
                            "Discuto fuertemente en contra",
                            "Estoy de acuerdo en la reunión pero me quejo después"
                        ]
                    },
                    {
                        "content": "Si el comportamiento de un colega te molesta, ¿qué harías?",
                        "options": [
                            "No digo nada pero me resiento",
                            "Lo hablo directamente con la persona",
                            "Me enojo visiblemente y confronto",
                            "Doy indirectas sutiles"
                        ]
                    },
                    {
                        "content": "Cuando logras algo importante en el trabajo, ¿cómo lo manejas?",
                        "options": [
                            "No lo menciono en absoluto",
                            "Lo comparto con confianza cuando es apropiado",
                            "Hablo de ello constantemente",
                            "Espero que otros lo noten"
                        ]
                    }
                ]
                
                for i, q_data in enumerate(questions_data, 1):
                    question = Question(
                        assessment_id=assessment.id,
                        content=q_data["content"],
                        question_type='multiple_choice',
                        options=q_data["options"],
                        correct_answer=1  # La segunda opción suele ser la más asertiva
                    )
                    db.session.add(question)
                
                db.session.commit()
                print("✅ Evaluación de asertividad inicializada")
                return True
            else:
                print("✅ Evaluación ya existe, verificando preguntas...")
                # Verificar si hay preguntas
                question_count = Question.query.filter_by(assessment_id=assessment.id).count()
                print(f"   Preguntas encontradas: {question_count}")
                if question_count == 0:
                    print("⚠️ No hay preguntas, creando preguntas de ejemplo...")
                    # Crear preguntas de ejemplo (solo unas pocas para verificar)
                    sample_questions = [
                        {
                            "content": "Cuando alguien critica tu trabajo de manera injusta, ¿cómo sueles responder?",
                            "options": [
                                "Permanezco en silencio para evitar el conflicto",
                                "Me defiendo con calma y hechos",
                                "Me enojo y me pongo a la defensiva",
                                "Intento cambiar de tema"
                            ]
                        },
                        {
                            "content": "Si un amigo te pide dinero repetidamente y no lo devuelve, ¿abordarías este tema?",
                            "options": [
                                "No, evitaría mencionarlo",
                                "Sí, tendría una conversación honesta al respecto",
                                "Dejaría de prestar pero no lo hablaría",
                                "Pondría excusas para no prestar más"
                            ]
                        }
                    ]
                    
                    for q_data in sample_questions:
                        question = Question(
                            assessment_id=assessment.id,
                            content=q_data["content"],
                            question_type='multiple_choice',
                            options=q_data["options"],
                            correct_answer=1
                        )
                        db.session.add(question)
                    
                    db.session.commit()
                    print("✅ Preguntas de ejemplo creadas")
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
    return render_template('coach_dashboard.html')

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
    """Obtener todos los coachees asignados al coach actual"""
    try:
        coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').all()
        
        coachees_data = []
        for coachee in coachees:
            # Contar evaluaciones completadas
            total_assessments = AssessmentResult.query.filter_by(user_id=coachee.id).count()
            
            # Obtener última evaluación
            latest_assessment = AssessmentResult.query.filter_by(user_id=coachee.id)\
                .order_by(AssessmentResult.completed_at.desc()).first()
            
            coachee_data = {
                'id': coachee.id,
                'full_name': coachee.full_name,
                'email': coachee.email,
                'username': coachee.username,
                'is_active': coachee.is_active,
                'created_at': coachee.created_at.isoformat() if coachee.created_at else None,
                'last_login': coachee.last_login.isoformat() if coachee.last_login else None,
                'total_assessments': total_assessments,
                'latest_assessment': {
                    'id': latest_assessment.id,
                    'score': latest_assessment.score,
                    'completed_at': latest_assessment.completed_at.isoformat(),
                    'result_text': latest_assessment.result_text
                } if latest_assessment else None
            }
            coachees_data.append(coachee_data)
        
        return jsonify(coachees_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/coachee/<int:coachee_id>/assessments', methods=['GET'])
@coach_access_required
def get_coachee_assessments(coachee_id):
    """Obtener todas las evaluaciones de un coachee específico"""
    try:
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id).first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no autorizado'}), 404
        
        assessments = AssessmentResult.query.filter_by(user_id=coachee_id)\
            .order_by(AssessmentResult.completed_at.desc()).all()
        
        assessments_data = []
        for assessment in assessments:
            assessments_data.append({
                'id': assessment.id,
                'assessment_id': assessment.assessment_id,
                'score': assessment.score,
                'total_questions': assessment.total_questions,
                'completed_at': assessment.completed_at.isoformat(),
                'result_text': assessment.result_text
            })
        
        return jsonify(assessments_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coach/coachee/<int:coachee_id>/latest-radar', methods=['GET'])
@coach_access_required  
def get_coachee_latest_radar(coachee_id):
    """Obtener datos del radar chart de la última evaluación del coachee"""
    try:
        # Verificar que el coachee pertenece al coach actual
        coachee = User.query.filter_by(id=coachee_id, coach_id=current_user.id).first()
        if not coachee:
            return jsonify({'error': 'Coachee no encontrado o no autorizado'}), 404
        
        # Obtener la última evaluación con detalles
        latest_assessment = AssessmentResult.query.filter_by(user_id=coachee_id)\
            .order_by(AssessmentResult.completed_at.desc()).first()
        
        if not latest_assessment:
            return jsonify({'error': 'No hay evaluaciones para este coachee'}), 404
        
        # Obtener las respuestas de la evaluación para calcular las dimensiones
        responses = Response.query.filter_by(
            user_id=coachee_id, 
            assessment_result_id=latest_assessment.id
        ).all()
        
        if not responses:
            return jsonify({'error': 'No se encontraron respuestas para la evaluación'}), 404
        
        # Calcular puntuaciones por dimensión (usando la misma lógica del radar original)
        # Asumiendo las mismas 5 dimensiones que en el sistema original
        dimensions = {
            'Autoafirmación': [],
            'Expresión de sentimientos negativos': [],
            'Expresión de sentimientos positivos': [],
            'Defensa de derechos': [],
            'Rechazo de peticiones': []
        }
        
        # Distribución de preguntas por dimensión (2 preguntas por dimensión)
        dimension_questions = {
            'Autoafirmación': [1, 2],
            'Expresión de sentimientos negativos': [3, 4], 
            'Expresión de sentimientos positivos': [5, 6],
            'Defensa de derechos': [7, 8],
            'Rechazo de peticiones': [9, 10]
        }
        
        # Agrupar respuestas por dimensión
        for response in responses:
            question_num = response.question_id
            for dimension, questions in dimension_questions.items():
                if question_num in questions:
                    dimensions[dimension].append(response.selected_option)
                    break
        
        # Calcular promedios por dimensión
        radar_data = {}
        for dimension, scores in dimensions.items():
            if scores:
                radar_data[dimension] = round(sum(scores) / len(scores), 2)
            else:
                radar_data[dimension] = 0
        
        return jsonify({
            'coachee_name': coachee.full_name,
            'assessment_date': latest_assessment.completed_at.isoformat(),
            'overall_score': latest_assessment.score,
            'radar_data': radar_data,
            'dimensions': list(radar_data.keys()),
            'values': list(radar_data.values())
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========================
# RUTAS DE PÁGINAS HTML
# ========================

@app.route('/login')
def login_page():
    """Página de login"""
    return render_template('login.html')

@app.route('/')
def index():
    """Página principal - redirige según el estado de autenticación"""
    if current_user.is_authenticated:
        return redirect(get_dashboard_url(current_user.role))
    else:
        return redirect('/login')

if __name__ == '__main__':
    print("🚀 Iniciando servidor Flask en puerto 5001...")
    app.run(debug=True, host='0.0.0.0', port=5001)
