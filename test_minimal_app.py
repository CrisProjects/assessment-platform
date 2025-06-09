#!/usr/bin/env python3
"""
MINIMAL FLASK APP FOR TESTING RENDER DEPLOYMENT
This will help us identify if the issue is with our main app or with Render itself
"""
from flask import Flask, jsonify
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1>RENDER DEPLOYMENT TEST</h1>
    <p>If you see this, the basic Flask app is working.</p>
    <p>Timestamp: {}</p>
    <a href="/test">Test API endpoint</a>
    """.format(datetime.utcnow().isoformat())

@app.route('/test')
def test():
    return jsonify({
        'status': 'success',
        'message': 'Minimal Flask app is working!',
        'timestamp': datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    app.run(debug=True)
