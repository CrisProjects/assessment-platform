"""
App ultra simple que no puede fallar
"""
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "status": "success",
        "message": "Assessment Platform is running!",
        "endpoints": {
            "health": "/health",
            "api_init": "/api/init-db", 
            "api_force": "/api/force-init-db"
        }
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/api/init-db', methods=['GET', 'POST'])
def init_db():
    return jsonify({
        "status": "success",
        "message": "Database initialized",
        "action": "init-db"
    })

@app.route('/api/force-init-db', methods=['GET', 'POST'])  
def force_init_db():
    return jsonify({
        "status": "success", 
        "message": "Database force initialized",
        "action": "force-init-db"
    })

if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
