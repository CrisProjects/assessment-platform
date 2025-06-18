"""
App Flask minimalista para debug de Render
"""
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def root():
    """Endpoint raíz ultra simple"""
    return jsonify({
        "status": "MINIMAL_APP_WORKING",
        "message": "Minimal Flask app is running on Render",
        "port": os.environ.get('PORT', 'not_set'),
        "python_version": "Working"
    })

@app.route('/health')
def health():
    """Health check simple"""
    return jsonify({"status": "healthy", "app": "minimal"})

@app.route('/api/test')
def api_test():
    """API test simple"""
    return jsonify({"message": "API working", "endpoint": "/api/test"})

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
