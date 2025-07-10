#!/usr/bin/env python3
"""
Aplicación Flask ultra-simplificada para Vercel
"""
import os
import sys

# Configuración para Vercel
os.environ['VERCEL'] = '1'
os.environ['PRODUCTION'] = '1'

# Agregar path de la raíz
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_path)

from flask import Flask, jsonify, render_template, request, redirect, url_for

# Crear app simplificada
app = Flask(__name__, 
            template_folder=os.path.join(root_path, 'templates'),
            static_folder=os.path.join(root_path, 'static'))

app.config['SECRET_KEY'] = 'vercel-simple-key'

@app.route('/')
def index():
    """Página principal"""
    try:
        return render_template('dashboard_selection.html')
    except:
        return jsonify({
            'status': 'success',
            'message': 'Assessment Platform - Vercel Deploy',
            'version': '1.0.0'
        })

@app.route('/api/status')
def api_status():
    """API de estado"""
    return jsonify({
        'status': 'success',
        'message': 'Assessment Platform API is running on Vercel',
        'version': '1.0.0'
    })

@app.route('/dashboard_selection')
def dashboard_selection():
    """Selección de dashboard"""
    return index()

@app.route('/coach-dashboard')
def coach_dashboard():
    """Dashboard del coach"""
    try:
        return render_template('coach_dashboard.html')
    except:
        return jsonify({'message': 'Coach Dashboard - Template not found'})

@app.route('/coachee-dashboard')
def coachee_dashboard():
    """Dashboard del coachee"""
    try:
        return render_template('coachee_dashboard.html')
    except:
        return jsonify({'message': 'Coachee Dashboard - Template not found'})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'error': 'Página no encontrada',
        'status': 404,
        'message': 'La ruta solicitada no existe'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Error interno del servidor',
        'status': 500,
        'message': str(error)
    }), 500

# Para Vercel
application = app

def handler(request):
    """Handler para Vercel"""
    return app(request.environ, lambda status, headers: None)
