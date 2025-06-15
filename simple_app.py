#!/usr/bin/env python3
"""
Versión ultra-simplificada para debug de Render
"""
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello from Render! Flask is working!"

@app.route('/coach-dashboard')
def coach_dashboard():
    return "Coach Dashboard - Coming Soon!"

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

# WSGI application
application = app
