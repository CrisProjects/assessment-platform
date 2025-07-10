#!/usr/bin/env python3
"""
WSGI entry point optimizado para Vercel (Serverless)
Configuración específica para funciones serverless
"""
import os
import sys
from werkzeug.serving import WSGIRequestHandler

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set Vercel-specific environment variables
os.environ['VERCEL'] = '1'
os.environ['PRODUCTION'] = '1'
os.environ['FLASK_ENV'] = 'production'

# Import and initialize the Flask app
try:
    from app_complete import app
    print("✅ VERCEL: App importada exitosamente")
    
    # Initialize database for Vercel (in app context)
    with app.app_context():
        try:
            from app_complete import auto_initialize_database
            auto_initialize_database()
            print("✅ VERCEL: Base de datos inicializada")
        except Exception as e:
            print(f"⚠️ VERCEL: Warning en DB init: {e}")
    
except Exception as e:
    print(f"❌ VERCEL: Error importando app: {e}")
    raise

# This is the main entry point for Vercel
def application(environ, start_response):
    """WSGI application entry point"""
    return app(environ, start_response)

# For compatibility
handler = application
app_instance = app

if __name__ == "__main__":
    # Local testing
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
