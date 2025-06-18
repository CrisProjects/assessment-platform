#!/usr/bin/env python3
"""
Versión mínima y robusta de la aplicación para verificar que el deployment funcione
"""
from flask import Flask, jsonify
import os

# Crear aplicación mínima
app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        'status': 'success',
        'message': 'Minimal Assessment Platform API is running',
        'version': '1.0.0-minimal'
    })

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': '2025-06-17'})

@app.route('/api/test')
def test():
    return jsonify({'test': 'working', 'message': 'Minimal API is functional'})

# Solo ejecutar si se llama directamente
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
