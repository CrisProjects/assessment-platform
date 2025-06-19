#!/usr/bin/env python3
"""
Minimal app para debugging en Render
"""
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "status": "success",
        "message": "Assessment Platform API",
        "version": "minimal-debug"
    })

@app.route('/api/health')
def health():
    return jsonify({
        "status": "healthy",
        "service": "assessment-platform-minimal"
    })

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
