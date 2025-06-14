#!/usr/bin/env python3
"""
Archivo de inicio simple para debugging en Render
"""
from flask import Flask, jsonify
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        'status': 'success',
        'message': '🚀 Assessment Platform está funcionando!',
        'timestamp': datetime.utcnow().isoformat(),
        'environment': os.environ.get('FLASK_ENV', 'unknown'),
        'port': os.environ.get('PORT', 'unknown')
    })

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'assessment-platform-backend',
        'version': '1.0.0'
    })

@app.route('/test')
def test():
    return jsonify({
        'message': 'Test endpoint working',
        'files_available': os.listdir('.'),
        'python_version': os.sys.version
    })

# Try to import the main app, but fallback gracefully
try:
    from app_complete import app as main_app
    print("✅ Main app imported successfully")
    # Use the main app
    application = main_app
except Exception as e:
    print(f"⚠️ Using fallback app due to error: {e}")
    # Use the simple fallback app
    application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    application.run(host='0.0.0.0', port=port, debug=False)
