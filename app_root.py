from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, jsonify
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

# Configurar CORS para permitir solicitudes desde Vercel
CORS(app, 
     origins=[
         'http://localhost:3000',
         'https://assessment-platform-4h58ggw5n-cris-projects-92f3df55.vercel.app',  # URL limpia final
         'https://assessment-platform-g18jyp9wv-cris-projects-92f3df55.vercel.app',  # URL anterior
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
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    questions = db.relationship('Question', backref='assessment', lazy=True)
    assessment_responses = db.relationship('AssessmentResponse', backref='assessment', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)
    options = db.Column(db.Text)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)

class AssessmentResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    participant_name = db.Column(db.String(100), nullable=False)
    responses = db.Column(db.JSON, nullable=False, default=dict)
    score = db.Column(db.Float)
    completed = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

# USER LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Inicializar la base de datos
def init_db():
    with app.app_context():
        db.create_all()
        
        # Crear usuario admin si no existe
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            
            # Crear evaluación de asertividad en español
            assessment = Assessment(
                title='Evaluación de Asertividad',
                description='Evaluación para medir el nivel de asertividad en diferentes situaciones',
                creator_id=admin_user.id
            )
            db.session.add(assessment)
            db.session.flush()  # Get the assessment ID
            
            # Add Spanish assertiveness questions
            questions = [
                {
                    'content': 'Cuando alguien critica tu trabajo de manera injusta, ¿cómo sueles responder?',
                    'type': 'multiple_choice',
                    'options': ['Permanezco en silencio para evitar el conflicto', 'Me defiendo con calma y hechos', 'Me enojo y me pongo a la defensiva', 'Intento cambiar de tema']
                },
                {
                    'content': 'Si un amigo te pide dinero repetidamente y no lo devuelve, ¿abordarías este tema?',
                    'type': 'multiple_choice',
                    'options': ['Sí, tendría una conversación honesta al respecto', 'No, evitaría mencionarlo', 'Dejaría de prestar pero no lo hablaría', 'Pondría excusas para no prestar más']
                },
                {
                    'content': '¿Con qué frecuencia expresas tu opinión en discusiones grupales?',
                    'type': 'multiple_choice',
                    'options': ['Siempre - Hablo sin importar la opinión de los demás', 'A menudo - Cuando el tema me importa mucho', 'A veces - Solo cuando me siento muy seguro', 'Rara vez - Suelo estar de acuerdo con la mayoría']
                },
                {
                    'content': 'Cuando alguien se cuela delante de ti en una fila, ¿qué sueles hacer?',
                    'type': 'multiple_choice',
                    'options': ['Señalo educadamente que hay una fila', 'No digo nada pero me frustro', 'Los confronto agresivamente', 'Dejo que se cuelen y evito el conflicto']
                },
                {
                    'content': '¿Cómo manejas las solicitudes que no quieres cumplir?',
                    'type': 'multiple_choice',
                    'options': ['Digo que no de forma clara y directa', 'Pongo excusas', 'Digo que sí aunque no quiera', 'Evito a la persona o la situación']
                },
                {
                    'content': 'Si tu comida en un restaurante no está preparada como la pediste, ¿qué harías?',
                    'type': 'multiple_choice',
                    'options': ['Expreso mis inquietudes educadamente al camarero', 'No digo nada pero dejo poca propina', 'Me quejo en voz alta y exijo ver al gerente', 'Nunca vuelvo al restaurante']
                },
                {
                    'content': '¿Cómo sueles reaccionar ante los cumplidos?',
                    'type': 'multiple_choice',
                    'options': ['Acepto los cumplidos con gratitud', 'Los minimizo o desvío', 'Me siento muy incómodo', 'Los rechazo completamente']
                },
                {
                    'content': 'Durante una reunión de equipo, ¿cómo respondes cuando no estás de acuerdo con una idea propuesta?',
                    'type': 'multiple_choice',
                    'options': ['Expreso mi desacuerdo respetuosamente y propongo alternativas', 'Me quedo callado y acepto', 'Discuto fuertemente en contra', 'Estoy de acuerdo en la reunión pero me quejo después']
                },
                {
                    'content': 'Si el comportamiento de un colega te molesta, ¿qué harías?',
                    'type': 'multiple_choice',
                    'options': ['Lo hablo directamente con la persona', 'Doy indirectas sutiles', 'Me enojo visiblemente y confronto', 'No digo nada pero me resiento']
                },
                {
                    'content': 'Cuando logras algo importante en el trabajo, ¿cómo lo manejas?',
                    'type': 'multiple_choice',
                    'options': ['Lo comparto con confianza cuando es apropiado', 'Espero que otros lo noten', 'No lo menciono en absoluto', 'Hablo de ello constantemente']
                }
            ]

            for q_data in questions:
                question = Question(
                    content=q_data['content'],
                    question_type=q_data['type'],
                    options=json.dumps(q_data['options']),
                    assessment_id=assessment.id
                )
                db.session.add(question)
            
            db.session.commit()

# Rutas básicas
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Plataforma de Evaluación de Asertividad</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="text-center">
                <h1>Plataforma de Evaluación de Asertividad</h1>
                <p class="lead">Bienvenido a nuestra plataforma de evaluación</p>
                <a href="/login" class="btn btn-primary">Iniciar Sesión</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return 'Usuario o contraseña incorrectos', 400
    
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Iniciar Sesión</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                            <h2 class="card-title text-center mb-4">Iniciar Sesión</h2>
                            <form method="POST">
                                <div class="mb-3">
                                    <label for="username" class="form-label">Usuario</label>
                                    <input type="text" class="form-control" id="username" name="username" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Contraseña</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-primary">Iniciar Sesión</button>
                                </div>
                            </form>
                            <div class="text-center mt-3">
                                <p><strong>Credenciales de prueba:</strong></p>
                                <p>Usuario: admin | Contraseña: admin123</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    assessments = Assessment.query.all()
    return f'''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Panel de Control</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Panel de Control</h2>
                <a href="/logout" class="btn btn-outline-danger">Cerrar Sesión</a>
            </div>
            <div class="alert alert-success">
                <h4>¡Bienvenido, {current_user.username}!</h4>
                <p>Has iniciado sesión correctamente en la Plataforma de Evaluación de Asertividad.</p>
            </div>
            <div class="row">
                {"".join([f'<div class="col-md-6 mb-4"><div class="card"><div class="card-body"><h5 class="card-title">{assessment.title}</h5><p class="card-text">{assessment.description}</p></div></div></div>' for assessment in assessments])}
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# API Routes for React frontend

# Manejador global para solicitudes OPTIONS (CORS preflight)
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        from flask import make_response
        response = make_response()
        
        # Obtener el origin de la request
        origin = request.headers.get('Origin')
        
        # Lista de origins permitidos
        allowed_origins = [
            'http://localhost:3000',
            'https://assessment-platform-4h58ggw5n-cris-projects-92f3df55.vercel.app',  # URL limpia final
            'https://assessment-platform-g18jyp9wv-cris-projects-92f3df55.vercel.app',  # URL anterior
            'https://assessment-platform-lg8l1boz6-cris-projects-92f3df55.vercel.app',
            'https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app'
        ]
        
        # Verificar si el origin está permitido
        if origin in allowed_origins:
            response.headers.add("Access-Control-Allow-Origin", origin)
        
        response.headers.add('Access-Control-Allow-Headers', "Content-Type, Authorization, Origin, Accept")
        response.headers.add('Access-Control-Allow-Methods', "GET, POST, PUT, DELETE, OPTIONS")
        response.headers.add('Access-Control-Allow-Credentials', "true")
        return response

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    try:
        data = request.get_json() if request.is_json else None
        
        # Support both JSON and form data
        if data:
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        
        if not username or not password:
            return jsonify({
                'success': False, 
                'error': 'Usuario y contraseña son requeridos'
            }), 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return jsonify({
                'success': True,
                'user': {
                    'username': user.username,
                    'is_admin': user.is_admin
                },
                'message': 'Login exitoso'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Usuario o contraseña incorrectos'
            }), 401
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@login_required
def api_logout():
    try:
        logout_user()
        return jsonify({
            'success': True,
            'message': 'Logout exitoso'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/assessments', methods=['GET', 'OPTIONS'])
@login_required
def api_assessments():
    assessments = Assessment.query.all()
    assessments_data = []
    for assessment in assessments:
        # Get actual questions from database
        questions_data = []
        for question in assessment.questions:
            questions_data.append({
                'id': question.id,
                'content': question.content,
                'question_type': question.question_type,
                'options': json.loads(question.options) if question.options else []
            })
        
        assessments_data.append({
            'id': assessment.id,
            'title': assessment.title,
            'description': assessment.description,
            'questions': questions_data,
            'created_at': assessment.created_at.isoformat() if assessment.created_at else None
        })
    return jsonify({'assessments': assessments_data})

@app.route('/api/assessment/<int:assessment_id>/save', methods=['POST', 'OPTIONS'])
@login_required
def api_save_assessment(assessment_id):
    try:
        data = request.get_json()
        user_id = current_user.id
        responses = data.get('responses', {})
        completed = data.get('completed', False)
        participant_name = data.get('participant_name', '')

        if not participant_name:
            return jsonify({
                'success': False,
                'error': 'El nombre del participante es requerido'
            }), 400

        # Find existing incomplete response or create new one
        response = AssessmentResponse.query.filter_by(
            user_id=user_id,
            assessment_id=assessment_id,
            completed=False
        ).first()

        if not response:
            response = AssessmentResponse(
                user_id=user_id,
                assessment_id=assessment_id,
                participant_name=participant_name,
                responses={},
                started_at=datetime.utcnow()
            )
            db.session.add(response)
        
        response.participant_name = participant_name
        response.responses = responses
        response.completed = completed

        if completed:
            response.completed_at = datetime.utcnow()
            assessment = Assessment.query.get(assessment_id)
            response.score = calculate_assertiveness_score(assessment, responses)

        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Progreso guardado exitosamente',
            'score': response.score if completed else None
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/results', methods=['GET', 'OPTIONS'])
@login_required
def api_results():
    try:
        participant = request.args.get('participant', 'all')
        
        completed_query = AssessmentResponse.query.filter_by(
            user_id=current_user.id,
            completed=True
        )
        
        in_progress_query = AssessmentResponse.query.filter_by(
            user_id=current_user.id,
            completed=False
        )
        
        if participant != 'all':
            completed_query = completed_query.filter_by(participant_name=participant)
            in_progress_query = in_progress_query.filter_by(participant_name=participant)
        
        completed_responses = [{
            'id': r.id,
            'assessment_id': r.assessment_id,
            'assessment_title': r.assessment.title,
            'participant_name': r.participant_name,
            'completed_at': r.completed_at.isoformat() if r.completed_at else None,
            'score': r.score,
            'responses': r.responses
        } for r in completed_query.all()]
        
        in_progress_responses = [{
            'id': r.id,
            'assessment_id': r.assessment_id,
            'assessment_title': r.assessment.title,
            'participant_name': r.participant_name,
            'started_at': r.started_at.isoformat() if r.started_at else None,
            'responses': r.responses
        } for r in in_progress_query.all()]
        
        return jsonify({
            'completed': completed_responses,
            'in_progress': in_progress_responses
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

# Scoring system for Spanish assertiveness assessment
RESPONSE_SCORES = {
    # Puntuación para cada opción (escala 0-3, 3 siendo la más asertiva)
    0: {"Permanezco en silencio para evitar el conflicto": 0, "Me defiendo con calma y hechos": 3, "Me enojo y me pongo a la defensiva": 1, "Intento cambiar de tema": 0},
    1: {"Sí, tendría una conversación honesta al respecto": 3, "No, evitaría mencionarlo": 0, "Dejaría de prestar pero no lo hablaría": 1, "Pondría excusas para no prestar más": 1},
    2: {"Siempre - Hablo sin importar la opinión de los demás": 2, "A menudo - Cuando el tema me importa mucho": 3, "A veces - Solo cuando me siento muy seguro": 1, "Rara vez - Suelo estar de acuerdo con la mayoría": 0},
    3: {"Señalo educadamente que hay una fila": 3, "No digo nada pero me frustro": 0, "Los confronto agresivamente": 1, "Dejo que se cuelen y evito el conflicto": 0},
    4: {"Digo que no de forma clara y directa": 3, "Pongo excusas": 1, "Digo que sí aunque no quiera": 0, "Evito a la persona o la situación": 0},
    5: {"Expreso mis inquietudes educadamente al camarero": 3, "No digo nada pero dejo poca propina": 1, "Me quejo en voz alta y exijo ver al gerente": 1, "Nunca vuelvo al restaurante": 0},
    6: {"Acepto los cumplidos con gratitud": 3, "Los minimizo o desvío": 1, "Me siento muy incómodo": 0, "Los rechazo completamente": 0},
    7: {"Expreso mi desacuerdo respetuosamente y propongo alternativas": 3, "Me quedo callado y acepto": 0, "Discuto fuertemente en contra": 1, "Estoy de acuerdo en la reunión pero me quejo después": 0},
    8: {"Lo hablo directamente con la persona": 3, "Doy indirectas sutiles": 1, "Me enojo visiblemente y confronto": 1, "No digo nada pero me resiento": 0},
    9: {"Lo comparto con confianza cuando es apropiado": 3, "Espero que otros lo noten": 1, "No lo menciono en absoluto": 0, "Hablo de ello constantemente": 1}
}

def calculate_assertiveness_score(assessment, responses):
    """Calculate the assertiveness score based on Spanish assessment responses"""
    total_points = 0
    max_points = len(assessment.questions) * 3  # Each question has a max score of 3
    
    for question in assessment.questions:
        answer = responses.get(str(question.id))
        if answer:
            # Find the question index based on the questions in the assessment
            question_list = list(assessment.questions)
            question_index = question_list.index(question)
            
            if question_index in RESPONSE_SCORES:
                score_map = RESPONSE_SCORES[question_index]
                total_points += score_map.get(answer, 0)
    
    return (total_points / max_points) * 100 if max_points > 0 else 0

# Inicializar la base de datos
if __name__ != '__main__':
    init_db()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
