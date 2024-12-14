from flask import Flask, jsonify, request
from flask_cors import CORS
from app import app, db, User, Assessment, AssessmentResponse
from datetime import datetime

# Enable CORS
CORS(app)

# API Routes
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        return jsonify({
            'status': 'success',
            'user': {
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin
            }
        })
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/api/assessments', methods=['GET'])
def api_get_assessments():
    assessments = Assessment.query.all()
    return jsonify({
        'assessments': [{
            'id': a.id,
            'title': a.title,
            'description': a.description,
            'creator_id': a.creator_id,
            'questions': [{
                'id': q.id,
                'content': q.content,
                'question_type': q.question_type,
                'options': q.options
            } for q in a.questions]
        } for a in assessments]
    })

@app.route('/api/assessment/<int:assessment_id>/save', methods=['POST'])
def api_save_progress(assessment_id):
    data = request.get_json()
    user_id = data.get('user_id')
    responses = data.get('responses', {})
    completed = data.get('completed', False)
    participant_name = data.get('participant_name', '')

    if not participant_name:
        return jsonify({'status': 'error', 'message': 'Participant name is required'})

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
        response.score = calculate_score(assessment, responses)

    try:
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/results', methods=['GET'])
def api_get_results():
    user_id = request.args.get('user_id')
    participant = request.args.get('participant', 'all')
    
    completed_query = AssessmentResponse.query.filter_by(
        user_id=user_id,
        completed=True
    )
    
    in_progress_query = AssessmentResponse.query.filter_by(
        user_id=user_id,
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
        'completed_at': r.completed_at.isoformat(),
        'score': r.score,
        'responses': r.responses
    } for r in completed_query.all()]
    
    in_progress_responses = [{
        'id': r.id,
        'assessment_id': r.assessment_id,
        'assessment_title': r.assessment.title,
        'participant_name': r.participant_name,
        'started_at': r.started_at.isoformat(),
        'responses': r.responses
    } for r in in_progress_query.all()]
    
    return jsonify({
        'completed': completed_responses,
        'in_progress': in_progress_responses
    })

if __name__ == '__main__':
    app.run(debug=True)
