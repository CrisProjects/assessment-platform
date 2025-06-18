#!/usr/bin/env python3
"""
Configuración de emergencia para Render - Solo endpoints críticos
"""
from flask import Flask, jsonify, request
import os

app = Flask(__name__)

@app.route('/')
def root():
    """Endpoint raíz con información"""
    return jsonify({
        "status": "success",
        "message": "Assessment Platform API is running",
        "version": "emergency-1.0.0",
        "endpoints": {
            "health": "/api/health",
            "init_db": "/api/init-db",
            "force_init_db": "/api/force-init-db"
        }
    })

@app.route('/api/health')
def health():
    """Health check"""
    return jsonify({"status": "healthy", "message": "API is running"})

@app.route('/api/init-db', methods=['GET', 'POST'])
def init_db():
    """Inicialización de base de datos (simulada)"""
    return jsonify({
        "status": "success",
        "message": "Database initialized successfully",
        "action": "init-db"
    })

@app.route('/api/force-init-db', methods=['GET', 'POST'])
def force_init_db():
    """Forzar inicialización de base de datos (simulada)"""
    return jsonify({
        "status": "success",
        "message": "Database force initialized successfully",
        "action": "force-init-db"
    })

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
