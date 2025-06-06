from src import app
from flask import request, jsonify
from datetime import datetime
import json

# Mock user for testing
MOCK_USER = {
    "id": 1,
    "username": "test@example.com",
    "password": "password123"
}

# Mock database for storing results (now as a class to maintain state)
class ResultsDatabase:
    def __init__(self):
        self.results = []
    
    def add_result(self, result):
        self.results.append(result)
    
    def get_results(self):
        return self.results

RESULTS_DB = ResultsDatabase()

ASSERTIVENESS_TEST = {
    'id': 1,
    'title': 'Assertiveness Assessment',
    'description': 'This assessment helps evaluate your assertiveness level in various social and professional situations.',
    'questions': [
        {
            'id': 1,
            'content': 'When someone criticizes your work, how do you typically respond?',
            'options': [
                'Get defensive and argue back',
                'Listen calmly and consider their perspective',
                'Remain silent and avoid confrontation',
                'Thank them for feedback and discuss constructively'
            ],
            'scores': [1, 3, 1, 4]  # Scoring for each option
        },
        {
            'id': 2,
            'content': 'In a group discussion, how do you usually express your opinion?',
            'options': [
                'Wait for others to ask for my input',
                'Speak up confidently while respecting others',
                'Dominate the conversation',
                'Rarely share my thoughts'
            ],
            'scores': [2, 4, 1, 1]
        },
        {
            'id': 3,
            'content': 'When you disagree with a friend\'s suggestion, what do you typically do?',
            'options': [
                'Go along with it to avoid conflict',
                'Express disagreement respectfully',
                'Become argumentative',
                'Change the subject'
            ],
            'scores': [1, 4, 1, 2]
        },
        {
            'id': 4,
            'content': 'How do you handle it when someone cuts in front of you in line?',
            'options': [
                'Say nothing and let it go',
                'Politely point out that there is a line',
                'Become confrontational',
                'Make passive-aggressive comments'
            ],
            'scores': [1, 4, 1, 2]
        },
        {
            'id': 5,
            'content': 'When you need help with a task, what do you usually do?',
            'options': [
                'Struggle alone without asking',
                'Clearly communicate your need for assistance',
                'Demand help immediately',
                'Drop hints hoping someone notices'
            ],
            'scores': [1, 4, 1, 2]
        }
    ]
}

def calculate_assertiveness_score(responses):
    total_score = 0
    max_possible = len(ASSERTIVENESS_TEST['questions']) * 4  # Maximum score per question is 4
    
    for question_id, answer_index in responses.items():
        question = next(q for q in ASSERTIVENESS_TEST['questions'] if str(q['id']) == question_id)
        total_score += question['scores'][int(answer_index)]
    
    percentage_score = (total_score / max_possible) * 100
    
    # Determine assertiveness level
    if percentage_score >= 80:
        level = "Highly Assertive"
        feedback = "You demonstrate excellent assertiveness skills, effectively balancing respect for others with self-advocacy."
    elif percentage_score >= 60:
        level = "Moderately Assertive"
        feedback = "You show good assertiveness in many situations but there might be room for improvement in certain scenarios."
    elif percentage_score >= 40:
        level = "Developing Assertiveness"
        feedback = "You're developing assertiveness skills but might benefit from practicing more direct communication."
    else:
        level = "Low Assertiveness"
        feedback = "Consider working on expressing your needs and opinions more directly while maintaining respect for others."
    
    return {
        'score': round(percentage_score, 1),
        'level': level,
        'feedback': feedback
    }

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username == MOCK_USER['username'] and password == MOCK_USER['password']:
        return jsonify({
            'status': 'success',
            'user': {
                'id': MOCK_USER['id'],
                'username': MOCK_USER['username']
            }
        })
    
    return jsonify({
        'status': 'error',
        'message': 'Invalid credentials'
    }), 401

@app.route('/api/assessments', methods=['GET'])
def get_assessments():
    # Remove scores from the response
    assessment_data = ASSERTIVENESS_TEST.copy()
    for question in assessment_data['questions']:
        question.pop('scores', None)
    
    return jsonify({'assessments': [assessment_data]})

@app.route('/api/assessment/<int:assessment_id>/save', methods=['POST'])
def save_assessment(assessment_id):
    try:
        data = request.get_json()
        app.logger.info(f"Received data: {json.dumps(data)}")
        
        if assessment_id != ASSERTIVENESS_TEST['id']:
            return jsonify({'error': 'Assessment not found'}), 404
        
        result = {
            'id': len(RESULTS_DB.get_results()) + 1,
            'assessment_id': assessment_id,
            'assessment_title': ASSERTIVENESS_TEST['title'],
            'participant_name': data['participant_name'],
            'responses': data['responses'],
            'completed': data['completed'],
            'started_at': datetime.now().isoformat(),
            'completed_at': datetime.now().isoformat() if data['completed'] else None
        }
        
        if data['completed']:
            result.update(calculate_assertiveness_score(data['responses']))
        
        RESULTS_DB.add_result(result)
        app.logger.info(f"Saved result: {json.dumps(result)}")
        
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        app.logger.error(f"Error saving assessment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/results', methods=['GET'])
def get_results():
    try:
        participant = request.args.get('participant', 'all')
        all_results = RESULTS_DB.get_results()
        app.logger.info(f"All results: {json.dumps(all_results)}")
        
        if participant == 'all':
            filtered_results = all_results
        else:
            filtered_results = [r for r in all_results if r['participant_name'] == participant]
        
        completed = [r for r in filtered_results if r['completed']]
        in_progress = [r for r in filtered_results if not r['completed']]
        
        response = {
            'completed': completed,
            'in_progress': in_progress
        }
        app.logger.info(f"Sending response: {json.dumps(response)}")
        
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Error getting results: {str(e)}")
        return jsonify({'error': str(e)}), 500
