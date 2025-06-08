from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

ASSERTIVENESS_CATEGORIES = {
    "Resolución de Conflictos": [0, 3, 8],  # Índices de preguntas para esta categoría
    "Comunicación": [2, 4, 6],
    "Entorno Profesional": [1, 7, 9],
    "Límites Personales": [3, 5, 8]
}

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

def get_score_category(score):
    if score >= 90:
        return "Excelente - Demuestras habilidades de asertividad muy sólidas"
    elif score >= 75:
        return "Bueno - Muestras asertividad saludable en la mayoría de las situaciones"
    elif score >= 50:
        return "Moderado - Tienes conductas asertivas pero hay margen de mejora"
    else:
        return "Necesita mejorar - Podrías beneficiarte de desarrollar más habilidades de comunicación asertiva"

def get_recommendations(scores_by_category):
    recomendaciones = []
    
    if scores_by_category.get("Resolución de Conflictos", 0) < 70:
        recomendaciones.append("Practica abordar los conflictos de manera directa pero calmada. Concéntrate en los hechos más que en las emociones.")
    
    if scores_by_category.get("Comunicación", 0) < 70:
        recomendaciones.append("Trabaja en expresar tus pensamientos y necesidades con claridad, respetando las perspectivas de los demás.")
    
    if scores_by_category.get("Entorno Profesional", 0) < 70:
        recomendaciones.append("Desarrolla estrategias de asertividad profesional, como preparar puntos clave antes de reuniones.")
    
    if scores_by_category.get("Límites Personales", 0) < 70:
        recomendaciones.append("Practica establecer y mantener límites personales claros en tus relaciones.")
    
    if not recomendaciones:
        recomendaciones.append("Continúa manteniendo tus sólidas habilidades de asertividad, sin perder de vista la empatía hacia los demás.")
    
    return recomendaciones

def get_answer_analysis(score):
    if score == 3:
        return "Respuesta asertiva excelente"
    elif score == 2:
        return "Buen equilibrio de asertividad"
    elif score == 1:
        return "Podrías ser más asertivo/a"
    else:
        return "Considera un enfoque más asertivo"

def get_conclusion(score):
    if score >= 90:
        return ("Demuestras excelentes habilidades de asertividad en diversas situaciones. "
                "Logras equilibrar el defender tus derechos con el respeto hacia los demás. "
                "Tu estilo de comunicación probablemente fomente relaciones sanas y respeto mutuo.")
    elif score >= 75:
        return ("Muestras buena asertividad en la mayoría de las situaciones. "
                "Generalmente puedes expresar tus necesidades y opiniones de manera efectiva. "
                "Hay áreas donde podrías potenciar tus habilidades, pero en general mantienes una comunicación saludable.")
    elif score >= 50:
        return ("Tienes un nivel moderado de asertividad con margen de mejora. "
                "Si bien muestras conductas asertivas en algunas situaciones, podrías beneficiarte de ser más directo/a y seguro/a al expresar tus necesidades y opiniones.")
    else:
        return ("Tus respuestas indican que a menudo adoptas un enfoque pasivo o agresivo en lugar de asertivo. "
                "Desarrollar habilidades de asertividad podría ayudarte a expresar mejor tus necesidades manteniendo el respeto por los demás. "
                "Enfócate en una comunicación clara, directa y en el establecimiento de límites.")

# SUGERENCIA: Para proyectos grandes, separar modelos, rutas y configuración en módulos distintos.

# Configuración secreta FIJA para evitar invalidar sesiones en cada reinicio
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')  # Cambia esto en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)  # Renombrado para claridad
    is_admin = db.Column(db.Boolean, default=False)
    assessments = db.relationship('Assessment', backref='creator', lazy=True)
    responses = db.relationship('Response', backref='user', lazy=True)
    assessment_responses = db.relationship('AssessmentResponse', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    questions = db.relationship('Question', backref='assessment', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    responses = db.relationship('Response', backref='assessment', lazy=True)
    assessment_responses = db.relationship('AssessmentResponse', backref='assessment', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)  # multiple_choice, text, etc.
    options = db.Column(db.Text)  # JSON string for multiple choice options
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    answers = db.relationship('Answer', backref='question', lazy=True)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.relationship('Answer', backref='response', lazy=True)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response_id = db.Column(db.Integer, db.ForeignKey('response.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    answer_content = db.Column(db.Text, nullable=False)

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter('from_json')
def from_json(value):
    if value:
        return json.loads(value)
    return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Validación básica
        if not username or not password:
            flash('Username and password are required')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all assessments
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    
    # Get statistics for each assessment
    assessment_stats = {}
    for assessment in assessments:
        stats = {
            'total_responses': AssessmentResponse.query.filter_by(
                assessment_id=assessment.id
            ).count(),
            'completed': AssessmentResponse.query.filter_by(
                assessment_id=assessment.id,
                completed=True
            ).count(),
            'in_progress': AssessmentResponse.query.filter_by(
                assessment_id=assessment.id,
                completed=False
            ).count(),
            'unique_participants': db.session.query(AssessmentResponse.participant_name)\
                .filter_by(assessment_id=assessment.id)\
                .distinct()\
                .count(),
            'average_score': db.session.query(func.avg(AssessmentResponse.score))\
                .filter_by(assessment_id=assessment.id, completed=True)\
                .scalar()
        }
        assessment_stats[assessment.id] = stats
    
    return render_template('dashboard.html', 
                         assessments=assessments,
                         assessment_stats=assessment_stats)

@app.route('/assessment/new', methods=['GET', 'POST'])
@login_required
def create_assessment():
    if request.method == 'POST':
        print(request.form)
        title = request.form.get('title')
        description = request.form.get('description')
        if not title:
            flash('Title is required')
            return redirect(url_for('create_assessment'))
        try:
            assessment = Assessment(
                title=title,
                description=description,
                creator_id=current_user.id
            )
            db.session.add(assessment)
            db.session.flush()  # Get the assessment ID

            # Process questions (nuevo método)
            i = 0
            while True:
                content = request.form.get(f'questions[{i}][content]')
                qtype = request.form.get(f'questions[{i}][type]')
                if not content:
                    break
                options = None
                if qtype == 'multiple_choice':
                    options = request.form.getlist(f'questions[{i}][options][]')
                    options = json.dumps(options)
                question = Question(
                    content=content,
                    question_type=qtype,
                    options=options,
                    assessment_id=assessment.id
                )
                db.session.add(question)
                i += 1

            db.session.commit()
            flash('Assessment created successfully!')
            return redirect(url_for('view_assessment', assessment_id=assessment.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating assessment: {str(e)}')
            return redirect(url_for('create_assessment'))
    return render_template('create_assessment.html')

@app.route('/assessment/<int:assessment_id>')
@login_required
def view_assessment(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    
    # Get the latest incomplete response or None
    in_progress_response = AssessmentResponse.query.filter_by(
        user_id=current_user.id,
        assessment_id=assessment_id,
        completed=False
    ).order_by(AssessmentResponse.started_at.desc()).first()
    
    # Ensure questions are ordered by id (or another field if needed)
    assessment.questions = sorted(assessment.questions, key=lambda q: q.id)
    
    # Pass saved_responses as a dict or None
    saved_responses = in_progress_response.responses if in_progress_response else None

    return render_template(
        'view_assessment_new.html', 
        assessment=assessment,
        saved_responses=saved_responses
    )

@app.route('/assessment/<int:assessment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_assessment(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    if assessment.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this assessment')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            assessment.title = request.form.get('title')
            assessment.description = request.form.get('description')

            # Elimina preguntas existentes
            for q in assessment.questions:
                db.session.delete(q)

            db.session.flush()

            i = 0
            while True:
                content = request.form.get(f'questions[{i}][content]')
                qtype = request.form.get(f'questions[{i}][type]')
                if not content:
                    break
                options = None
                if qtype == 'multiple_choice':
                    opts = request.form.getlist(f'questions[{i}][options][]')
                    options = json.dumps(opts)
                question = Question(
                    content=content,
                    question_type=qtype,
                    options=options,
                    assessment_id=assessment.id
                )
                db.session.add(question)
                i += 1

            db.session.commit()
            flash('Assessment updated successfully!')
            return redirect(url_for('view_assessment', assessment_id=assessment.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating assessment: {str(e)}')

    return render_template('edit_assessment.html', assessment=assessment)


@app.route('/assessment/<int:assessment_id>/submit', methods=['POST'])
@login_required
def submit_assessment(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    
    # Create a new response
    response = AssessmentResponse(
        user_id=current_user.id,
        assessment_id=assessment_id,
        responses={},
        completed=True,
        completed_at=datetime.utcnow()
    )
    
    # Get answers from form
    for question in assessment.questions:
        answer = request.form.get(f'question_{question.id}')
        if answer:
            response.responses[str(question.id)] = answer
    
    # Calculate score
    response.score = calculate_score(assessment, response.responses)
    
    db.session.add(response)
    db.session.commit()
    
    flash('Assessment submitted successfully')
    return redirect(url_for('view_results', assessment_id=assessment_id, response_id=response.id))

def calculate_score(assessment, responses):
    total_points = 0
    max_points = len(assessment.questions) * 3  # Each question has a max score of 3
    
    for question in assessment.questions:
        answer = responses.get(str(question.id))
        if answer:
            question_index = list(assessment.questions).index(question)
            if question_index in RESPONSE_SCORES:
                score_map = RESPONSE_SCORES[question_index]
                total_points += score_map.get(answer, 0)
    
    return (total_points / max_points) * 100 if max_points > 0 else 0

@app.route('/assessment/<int:assessment_id>/save', methods=['POST'])
@login_required
def save_progress(assessment_id):
    data = request.get_json()
    responses = data.get('responses', {})
    completed = data.get('completed', False)
    participant_name = data.get('participant_name', '')

    if not participant_name:
        return jsonify({'status': 'error', 'message': 'Participant name is required'})

    # Remove participant_name from responses dict if it exists
    if 'participant_name' in responses:
        del responses['participant_name']

    # Check for existing in-progress response
    response = AssessmentResponse.query.filter_by(
        user_id=current_user.id,
        assessment_id=assessment_id,
        completed=False
    ).first()

    if not response:
        response = AssessmentResponse(
            user_id=current_user.id,
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
        response.score = calculate_score(assessment, responses)

    try:
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        print(f"Error saving response: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error saving response'})

@app.route('/results')
@login_required
def view_results_list():
    # Get selected participant from query params
    selected_participant = request.args.get('participant', 'all')
    
    # Get all unique participants for the filter dropdown
    if current_user.is_admin:
        participants = db.session.query(AssessmentResponse.participant_name)\
            .distinct()\
            .all()
        # Base query for completed responses (all users)
        completed_query = AssessmentResponse.query.filter_by(completed=True)
        in_progress_query = AssessmentResponse.query.filter_by(completed=False)
    else:
        participants = db.session.query(AssessmentResponse.participant_name)\
            .filter_by(user_id=current_user.id)\
            .distinct()\
            .all()
        # Base query for completed responses (current user only)
        completed_query = AssessmentResponse.query.filter_by(
            user_id=current_user.id,
            completed=True
        )
        in_progress_query = AssessmentResponse.query.filter_by(
            user_id=current_user.id,
            completed=False
        )
    participants = [p[0] for p in participants]  # Convert from tuples to list

    # Apply participant filter if one is selected
    if selected_participant != 'all':
        completed_query = completed_query.filter_by(participant_name=selected_participant)
        in_progress_query = in_progress_query.filter_by(participant_name=selected_participant)

    # Get filtered results
    completed_responses = completed_query.order_by(AssessmentResponse.completed_at.desc()).all()
    in_progress_responses = in_progress_query.order_by(AssessmentResponse.started_at.desc()).all()

    return render_template('results_list_new.html', 
                         completed_responses=completed_responses,
                         in_progress_responses=in_progress_responses,
                         participants=participants,
                         selected_participant=selected_participant)

@app.route('/assessment/<int:assessment_id>/results/<int:response_id>')
@login_required
def view_results(assessment_id, response_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    response = AssessmentResponse.query.get_or_404(response_id)
    
    if response.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view these results')
        return redirect(url_for('dashboard'))
    
    score = response.score
    
    # Calculate category scores
    category_scores = {}
    for category, question_indices in ASSERTIVENESS_CATEGORIES.items():
        category_total = 0
        category_max = len(question_indices) * 3
        
        for idx in question_indices:
            question = assessment.questions[idx]
            answer = response.responses.get(str(question.id))
            if answer:
                score_map = RESPONSE_SCORES[idx]
                category_total += score_map.get(answer, 0)
        
        category_scores[category] = (category_total / category_max * 100) if category_max > 0 else 0
    
    # Get analysis and recommendations
    conclusion = get_conclusion(score)
    recommendations = get_recommendations(category_scores)
    answer_analysis = get_answer_analysis(score)
    
    return render_template('assessment_results.html',
                         assessment=assessment,
                         response=response,
                         score=score,
                         category_scores=category_scores,
                         conclusion=conclusion,
                         recommendations=recommendations,
                         answer_analysis=answer_analysis)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def init_db():
    with app.app_context():
        # SUGERENCIA: Usa Flask-Migrate para migraciones en vez de create_all() en producción
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

        # Create assertiveness assessment if it doesn't exist (busca por título en español)
        assertiveness = Assessment.query.filter_by(title='Evaluación de Asertividad').first()
        if not assertiveness:
            assertiveness = Assessment(
                title='Evaluación de Asertividad',
                description='Evalúa tus habilidades de asertividad en diversas situaciones. Esta evaluación te ayudará a comprender tu estilo de comunicación y te brindará recomendaciones para mejorar.',
                creator_id=admin.id
            )
            db.session.add(assertiveness)
            db.session.flush()  # Get the assessment ID

            # Add questions (translated to Spanish)
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
                    assessment_id=assertiveness.id
                )
                db.session.add(question)

            db.session.commit()
            print("¡Evaluación de asertividad creada exitosamente!")

if __name__ == '__main__':
    init_db()  # Inicializa la base de datos antes de correr la app
    app.run(debug=True)
