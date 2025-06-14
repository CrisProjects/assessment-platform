#!/usr/bin/env python3
"""
WSGI entry point optimizado para Render
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the complete application with proper error handling
try:
    from app_complete import app
    print("✅ App importada exitosamente")
    
    # Initialize database in production if needed
    with app.app_context():
        from app_complete import db, init_database
        try:
            db.create_all()
            init_database()
            print("✅ Base de datos inicializada")
        except Exception as e:
            print(f"⚠️ Warning during DB init: {e}")
    
except Exception as e:
    print(f"❌ Error importing app: {e}")
    # Create a minimal fallback app
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    @app.route('/health')
    def health():
        return jsonify({
            'status': 'error',
            'message': 'Application failed to initialize',
            'error': str(e)
        }), 500

# This is what Render will import
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
