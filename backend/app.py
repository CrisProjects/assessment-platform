from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Mock user for testing
MOCK_USER = {
    "id": 1,
    "username": "test@example.com",
    "password": "password123"
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
    # Mock assessment data
    assessments = [
        {
            'id': 1,
            'title': 'Sample Assessment',
            'description': 'This is a sample assessment to test the platform.',
            'questions': [
                {
                    'id': 1,
                    'content': 'What is 2 + 2?',
                    'options': ['3', '4', '5', '6']
                },
                {
                    'id': 2,
                    'content': 'Which planet is closest to the Sun?',
                    'options': ['Venus', 'Mars', 'Mercury', 'Earth']
                }
            ]
        }
    ]
    return jsonify({'assessments': assessments})

if __name__ == '__main__':
    app.run(debug=True)
