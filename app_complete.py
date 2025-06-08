#!/usr/bin/env python3
"""
Aplicación Flask completa con frontend y backend integrados
Perfecta para desplegar en Render como un solo servicio
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
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
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        login_user(user)
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
        return jsonify({'success': False, 'error': 'Credenciales inválidas'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logout exitoso'})

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

def init_database():
    """Inicializar la base de datos con datos de muestra"""
    with app.app_context():
        db.create_all()
        
        # Verificar si ya existen datos
        if User.query.first() is None:
            # Crear usuario admin
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            
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
            print("✅ Base de datos inicializada con datos de muestra")

if __name__ == '__main__':
    init_database()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
