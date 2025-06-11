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

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-fixed-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurar CORS
CORS(app, supports_credentials=True)

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

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), default='multiple_choice')
    options = db.Column(db.JSON)
    correct_answer = db.Column(db.Integer)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_option = db.Column(db.Integer)
    option_text = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

class AssessmentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    score = db.Column(db.Float)
    total_questions = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    result_text = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas del Frontend
@app.route('/')
def index():
    """Página principal con el frontend integrado"""
    return send_from_directory('.', 'index.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204

# API Routes
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"[DEBUG] Login attempt for user: {username}")
        
        # Verificar que la base de datos esté disponible
        try:
            user = User.query.filter_by(username=username).first()
            print(f"[DEBUG] User found: {user is not None}")
        except Exception as db_error:
            print(f"[DEBUG] Database error: {db_error}")
            # Intentar inicializar la base de datos
            init_result = init_database()
            print(f"[DEBUG] Database init result: {init_result}")
            user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            print(f"[DEBUG] Login successful for: {username}")
            return jsonify({
                'success': True,
                'message': 'Login exitoso',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin
                }
            })
        else:
            print(f"[DEBUG] Login failed for: {username}")
            return jsonify({'success': False, 'error': 'Credenciales inválidas'}), 401
            
    except Exception as e:
        print(f"[ERROR] Login endpoint error: {e}")
        return jsonify({'success': False, 'error': f'Error del servidor: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logout exitoso'})

@app.route('/api/register', methods=['POST'])
def api_register():
    """Endpoint para registro de usuarios o datos demográficos"""
    data = request.get_json()
    
    # Si el usuario está autenticado, esto es para datos demográficos
    if current_user.is_authenticated:
        # Guardar datos demográficos del usuario actual
        name = data.get('name')
        email = data.get('email')
        age = data.get('age')
        gender = data.get('gender')
        
        if not all([name, email, age, gender]):
            return jsonify({'success': False, 'error': 'Todos los campos demográficos son requeridos'}), 400
        
        # Almacenar temporalmente en la sesión para la evaluación
        session['participant_data'] = {
            'name': name,
            'email': email,
            'age': age,
            'gender': gender
        }
        
        return jsonify({
            'success': True,
            'message': 'Datos demográficos registrados exitosamente',
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'is_admin': current_user.is_admin,
                'participant_data': session['participant_data']
            }
        })
    
    # Si no está autenticado, es un registro de usuario normal
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Usuario y contraseña son requeridos'}), 400
    
    # Verificar si el usuario ya existe
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'El usuario ya existe'}), 400
    
    # Crear nuevo usuario
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    # Login automático después del registro
    login_user(user)
    
    return jsonify({
        'success': True,
        'message': 'Usuario registrado exitosamente',
        'user': {
            'id': user.id,
            'username': user.username,
            'is_admin': user.is_admin
        }
    })

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
@login_required
def api_get_questions():
    """Endpoint para obtener todas las preguntas de la evaluación de asertividad"""
    # Obtener la primera evaluación (evaluación de asertividad)
    assessment = Assessment.query.first()
    if not assessment:
        return jsonify({'error': 'No se encontró la evaluación'}), 404
    
    questions = Question.query.filter_by(assessment_id=assessment.id).all()
    questions_data = []
    
    for question in questions:
        questions_data.append({
            'id': question.id,
            'content': question.content,
            'question_type': question.question_type,
            'options': question.options
        })
    
    return jsonify({'questions': questions_data})

@app.route('/api/save_assessment', methods=['POST'])
@login_required
def api_save_assessment():
    data = request.get_json()
    assessment_id = data.get('assessment_id')
    responses_data = data.get('responses', [])
    
    # Calcular puntuación
    total_questions = len(responses_data)
    assertive_score = 0
    
    for response_data in responses_data:
        question_id = response_data.get('question_id')
        selected_option = response_data.get('selected_option')
        option_text = response_data.get('option_text')
        
        # Guardar respuesta
        response = Response(
            user_id=current_user.id,
            question_id=question_id,
            selected_option=selected_option,
            option_text=option_text
        )
        db.session.add(response)
        
        # Puntuación para asertividad (opción 1 = más asertiva)
        if selected_option == 1:
            assertive_score += 4
        elif selected_option == 0:
            assertive_score += 3
        elif selected_option == 2:
            assertive_score += 1
        else:
            assertive_score += 0
    
    # Calcular porcentaje
    max_score = total_questions * 4
    percentage = round((assertive_score / max_score) * 100, 1)
    
    # Determinar nivel y texto de resultado
    if percentage >= 80:
        score_level = "Muy Asertivo"
        result_text = "¡Excelente! Tienes un nivel muy alto de asertividad. Sabes comunicarte de manera clara y directa, respetando tanto tus derechos como los de los demás. Continúa desarrollando estas habilidades."
    elif percentage >= 60:
        score_level = "Asertivo"
        result_text = "¡Muy bien! Tienes un buen nivel de asertividad. En la mayoría de situaciones sabes expresar tus opiniones y necesidades de manera apropiada. Hay oportunidades para seguir mejorando."
    elif percentage >= 40:
        score_level = "Moderadamente Asertivo"
        result_text = "Tienes un nivel moderado de asertividad. En algunas situaciones te expresas bien, pero en otras podrías ser más directo o más diplomático. Te beneficiarías de desarrollar más estas habilidades."
    else:
        score_level = "Poco Asertivo"
        result_text = "Tu nivel de asertividad es bajo. Esto puede llevarte a situaciones de conflicto o frustración. Te recomendamos trabajar en desarrollar habilidades de comunicación asertiva para mejorar tus relaciones."
    
    # Guardar resultado
    result = AssessmentResult(
        user_id=current_user.id,
        assessment_id=assessment_id,
        score=percentage,
        total_questions=total_questions,
        result_text=result_text
    )
    db.session.add(result)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'score': percentage,
        'score_level': score_level,
        'result_text': result_text,
        'total_questions': total_questions
    })

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

def init_database():
    """Inicializar la base de datos con datos de muestra"""
    try:
        with app.app_context():
            db.create_all()
            
            # Verificar si ya existen usuarios admin
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                print("🔄 Creando usuario admin...")
                admin_user = User(username='admin', is_admin=True)
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
            
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

# Inicializar la base de datos automáticamente cuando la aplicación arranque
with app.app_context():
    try:
        # Siempre crear las tablas
        db.create_all()
        
        # Verificar/crear usuario admin
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            print("🔧 Creando usuario admin de emergencia...")
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Usuario admin creado exitosamente")
        
        # Ejecutar inicialización completa
        init_database()
    except Exception as e:
        print(f"⚠️ No se pudo inicializar la base de datos automáticamente: {e}")
        # Crear usuario de emergencia sin depender de init_database
        try:
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', is_admin=True)
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Usuario admin de emergencia creado")
        except Exception as emergency_error:
            print(f"❌ Error crítico creando usuario de emergencia: {emergency_error}")

@app.route('/api/demographics', methods=['POST'])
@login_required
def api_demographics():
    """Endpoint específico para registrar datos demográficos"""
    data = request.get_json()
    
    name = data.get('name')
    email = data.get('email')
    age = data.get('age')
    gender = data.get('gender')
    
    if not all([name, email, age, gender]):
        return jsonify({'success': False, 'error': 'Todos los campos demográficos son requeridos'}), 400
    
    # Almacenar en la sesión para la evaluación
    session['participant_data'] = {
        'name': name,
        'email': email,
        'age': age,
        'gender': gender
    }
    
    return jsonify({
        'success': True,
        'message': 'Datos demográficos registrados exitosamente',
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'is_admin': current_user.is_admin,
            'participant_data': session['participant_data']
        }
    })

if __name__ == '__main__':
    init_database()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
