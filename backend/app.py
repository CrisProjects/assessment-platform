from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

# Configuración secreta FIJA para evitar invalidar sesiones en cada reinicio
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')  # Cambia esto en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
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
    question_type = db.Column(db.String(20), nullable=False)
    options = db.Column(db.Text)
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

def init_db():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        assertiveness = Assessment.query.filter_by(title='Evaluación de Asertividad').first()
        if not assertiveness:
            assertiveness = Assessment(
                title='Evaluación de Asertividad',
                description='Evalúa tus habilidades de asertividad en diversas situaciones. Esta evaluación te ayudará a comprender tu estilo de comunicación y te brindará recomendaciones para mejorar.',
                creator_id=admin.id
            )
            db.session.add(assertiveness)
            db.session.flush()
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

@app.route('/')
def index():
    return render_template('index.html')

# El bloque siguiente solo debe usarse en desarrollo local, no en producción/Render
if __name__ == '__main__':
    init_db()  # Inicializa la base de datos antes de correr la app
    app.run(debug=True)
