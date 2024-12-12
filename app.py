from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from dotenv import load_dotenv
load_dotenv()

ASSERTIVENESS_CATEGORIES = {
    "Conflict Resolution": [0, 3, 8],  # Question indices for this category
    "Communication": [2, 4, 6],
    "Professional Setting": [1, 7, 9],
    "Personal Boundaries": [3, 5, 8]
}

RESPONSE_SCORES = {
    # Scoring for each option (0-3 scale, 3 being most assertive)
    0: {"I remain silent to avoid conflict": 0, "I defend myself calmly with facts": 3, "I become angry and defensive": 1, "I try to change the subject": 0},
    1: {"Yes, I would have an honest conversation about it": 3, "No, I would avoid mentioning it": 0, "I would stop lending but not discuss it": 1, "I would make excuses to not lend anymore": 1},
    2: {"Always - I speak up regardless of others' opinions": 2, "Often - When I feel strongly about the topic": 3, "Sometimes - Only when I feel very confident": 1, "Rarely - I usually agree with the majority": 0},
    3: {"Politely point out that there is a line": 3, "Say nothing but feel frustrated": 0, "Confront them aggressively": 1, "Let them cut and avoid confrontation": 0},
    4: {"Say no clearly and directly": 3, "Make up excuses": 1, "Say yes even though I don't want to": 0, "Avoid the person or situation": 0},
    5: {"Raise concerns politely with the server": 3, "Say nothing but leave a poor tip": 1, "Complain loudly and demand to see a manager": 1, "Never return to the restaurant": 0},
    6: {"Accept them graciously": 3, "Deflect or minimize them": 1, "Feel very uncomfortable": 0, "Reject them outright": 0},
    7: {"Express disagreement respectfully with alternatives": 3, "Stay silent and go along with it": 0, "Argue strongly against it": 1, "Agree in the meeting but complain to colleagues later": 0},
    8: {"Discuss it directly with them": 3, "Drop subtle hints about it": 1, "Get visibly angry and confront them": 1, "Say nothing but feel resentful": 0},
    9: {"Share it confidently when appropriate": 3, "Wait for others to notice": 1, "Don't mention it at all": 0, "Constantly talk about it": 1}
}

def get_score_category(score):
    if score >= 90:
        return "Excellent - You demonstrate strong assertiveness skills"
    elif score >= 75:
        return "Good - You show healthy assertiveness in most situations"
    elif score >= 50:
        return "Moderate - You have some assertive behaviors but there's room for improvement"
    else:
        return "Needs Improvement - You might benefit from developing more assertive communication skills"

def get_recommendations(scores_by_category):
    recommendations = []
    
    if scores_by_category.get("Conflict Resolution", 0) < 70:
        recommendations.append("Practice addressing conflicts directly but calmly. Focus on facts rather than emotions.")
    
    if scores_by_category.get("Communication", 0) < 70:
        recommendations.append("Work on expressing your thoughts and needs clearly while respecting others' perspectives.")
    
    if scores_by_category.get("Professional Setting", 0) < 70:
        recommendations.append("Develop strategies for professional assertiveness, such as preparing talking points before meetings.")
    
    if scores_by_category.get("Personal Boundaries", 0) < 70:
        recommendations.append("Practice setting and maintaining clear personal boundaries in your relationships.")
    
    if not recommendations:
        recommendations.append("Continue maintaining your strong assertiveness skills while staying mindful of others' perspectives.")
    
    return recommendations

def get_answer_analysis(score):
    if score == 3:
        return "Excellent assertive response"
    elif score == 2:
        return "Good balance of assertiveness"
    elif score == 1:
        return "Could be more assertive"
    else:
        return "Consider a more assertive approach"

def get_conclusion(score):
    if score >= 90:
        return """You demonstrate excellent assertiveness skills across various situations. You effectively balance 
                standing up for yourself while respecting others. Your communication style is likely to foster healthy 
                relationships and mutual respect."""
    elif score >= 75:
        return """You show good assertiveness in most situations. You're generally able to express your needs and 
                opinions effectively. There are some areas where you might enhance your assertiveness skills, but 
                overall you maintain a healthy communication style."""
    elif score >= 50:
        return """You display moderate assertiveness with room for improvement. While you show assertive behavior in 
                some situations, there are areas where you might benefit from being more direct and confident in 
                expressing your needs and opinions."""
    else:
        return """Your responses indicate that you often take a passive or aggressive approach rather than an 
                assertive one. Developing assertiveness skills could help you better express your needs while 
                maintaining respect for others. Consider focusing on clear, direct communication and boundary-setting."""

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///assessments.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    assessments = db.relationship('Assessment', backref='creator', lazy=True)
    responses = db.relationship('Response', backref='user', lazy=True)
    assessment_responses = db.relationship('AssessmentResponse', backref='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

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
        title = request.form.get('title')
        description = request.form.get('description')
        
        assessment = Assessment(
            title=title,
            description=description,
            creator_id=current_user.id
        )
        db.session.add(assessment)
        db.session.flush()  # Get the assessment ID
        
        # Process questions
        question_contents = request.form.getlist('questions[][content]')
        question_types = request.form.getlist('questions[][type]')
        
        for i in range(len(question_contents)):
            options = None
            if question_types[i] == 'multiple_choice':
                # Get all options for this question
                options_key = f'questions[{i}][options][]'
                options = request.form.getlist(options_key)
                options = json.dumps(options)  # Convert to JSON string for storage
            
            question = Question(
                content=question_contents[i],
                question_type=question_types[i],
                options=options,
                assessment_id=assessment.id
            )
            db.session.add(question)
        
        db.session.commit()
        flash('Assessment created successfully!')
        return redirect(url_for('view_assessment', assessment_id=assessment.id))
    
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
    
    return render_template('view_assessment_new.html', 
                         assessment=assessment,
                         saved_responses=in_progress_response.responses if in_progress_response else None)

@app.route('/assessment/<int:assessment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_assessment(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    if assessment.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this assessment')
        return redirect(url_for('dashboard'))
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
    participants = db.session.query(AssessmentResponse.participant_name)\
        .filter_by(user_id=current_user.id)\
        .distinct()\
        .all()
    participants = [p[0] for p in participants]  # Convert from tuples to list
    
    # Base query for completed responses
    completed_query = AssessmentResponse.query.filter_by(
        user_id=current_user.id,
        completed=True
    )
    
    # Base query for in-progress responses
    in_progress_query = AssessmentResponse.query.filter_by(
        user_id=current_user.id,
        completed=False
    )
    
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
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

        # Create assertiveness assessment if it doesn't exist
        assertiveness = Assessment.query.filter_by(title='Assertiveness Assessment').first()
        if not assertiveness:
            assertiveness = Assessment(
                title='Assertiveness Assessment',
                description='Evaluate your assertiveness skills in various situations. This assessment will help you understand your communication style and provide recommendations for improvement.',
                creator_id=admin.id
            )
            db.session.add(assertiveness)
            db.session.flush()  # Get the assessment ID

            # Add questions
            questions = [
                {
                    'content': 'When someone criticizes your work unfairly, how do you typically respond?',
                    'type': 'multiple_choice',
                    'options': ['I remain silent to avoid conflict', 'I defend myself calmly with facts', 'I become angry and defensive', 'I try to change the subject']
                },
                {
                    'content': 'If a friend repeatedly borrows money without repaying, would you address this issue?',
                    'type': 'multiple_choice',
                    'options': ['Yes, I would have an honest conversation about it', 'No, I would avoid mentioning it', 'I would stop lending but not discuss it', 'I would make excuses to not lend anymore']
                },
                {
                    'content': 'How often do you express your opinion in group discussions?',
                    'type': 'multiple_choice',
                    'options': ['Always - I speak up regardless of others\' opinions', 'Often - When I feel strongly about the topic', 'Sometimes - Only when I feel very confident', 'Rarely - I usually agree with the majority']
                },
                {
                    'content': 'When someone cuts in line in front of you, what do you typically do?',
                    'type': 'multiple_choice',
                    'options': ['Politely point out that there is a line', 'Say nothing but feel frustrated', 'Confront them aggressively', 'Let them cut and avoid confrontation']
                },
                {
                    'content': 'How do you handle requests that you don\'t want to fulfill?',
                    'type': 'multiple_choice',
                    'options': ['Say no clearly and directly', 'Make up excuses', 'Say yes even though I don\'t want to', 'Avoid the person or situation']
                },
                {
                    'content': 'If your meal at a restaurant isn\'t prepared as requested, what would you do?',
                    'type': 'multiple_choice',
                    'options': ['Raise concerns politely with the server', 'Say nothing but leave a poor tip', 'Complain loudly and demand to see a manager', 'Never return to the restaurant']
                },
                {
                    'content': 'How do you typically handle compliments?',
                    'type': 'multiple_choice',
                    'options': ['Accept them graciously', 'Deflect or minimize them', 'Feel very uncomfortable', 'Reject them outright']
                },
                {
                    'content': 'During a team meeting, how do you respond when you disagree with a proposed idea?',
                    'type': 'multiple_choice',
                    'options': ['Express disagreement respectfully with alternatives', 'Stay silent and go along with it', 'Argue strongly against it', 'Agree in the meeting but complain to colleagues later']
                },
                {
                    'content': 'If a colleague\'s behavior is bothering you, what would you do?',
                    'type': 'multiple_choice',
                    'options': ['Discuss it directly with them', 'Drop subtle hints about it', 'Get visibly angry and confront them', 'Say nothing but feel resentful']
                },
                {
                    'content': 'When you achieve something significant at work, how do you handle it?',
                    'type': 'multiple_choice',
                    'options': ['Share it confidently when appropriate', 'Wait for others to notice', 'Don\'t mention it at all', 'Constantly talk about it']
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
            print("Assertiveness assessment created successfully!")

if __name__ == '__main__':
    init_db()  # Initialize database before running the app
    app.run(debug=True)
