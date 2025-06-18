#!/usr/bin/env python3
"""
App de prueba minimalista para debug
"""
from flask import Flask, jsonify, render_template, redirect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-key'

@app.route('/')
def index():
    return jsonify({
        'status': 'OK',
        'message': 'Aplicación de prueba funcionando',
        'version': '1.0'
    })

@app.route('/test-dashboard')
def test_dashboard():
    return jsonify({
        'status': 'OK',
        'message': 'Dashboard de prueba funcionando'
    })

@app.route('/test-redirect')
def test_redirect():
    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
