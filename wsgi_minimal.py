#!/usr/bin/env python3
"""
Minimal WSGI application for testing Render deployment
"""
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        'status': 'success',
        'message': 'Minimal Flask app is running on Render',
        'timestamp': '2025-06-15T00:40:00Z'
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

# This is what Render will import
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
