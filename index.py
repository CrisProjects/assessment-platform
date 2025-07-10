#!/usr/bin/env python3
"""
Entry point principal para Vercel
Alternativa a wsgi_vercel.py - Configuración optimizada
"""
import os
import sys

# Configurar entorno para Vercel
os.environ['VERCEL'] = '1'
os.environ['PRODUCTION'] = '1'
os.environ['FLASK_ENV'] = 'production'

# Agregar directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import the Flask application
    from app_complete import app
    
    # Initialize database
    with app.app_context():
        try:
            from app_complete import auto_initialize_database
            auto_initialize_database()
            print("✅ INDEX: Base de datos inicializada")
        except Exception as e:
            print(f"⚠️ INDEX: Warning en DB init: {e}")
    
    # WSGI application for Vercel
    def application(environ, start_response):
        """WSGI application entry point"""
        return app.wsgi_app(environ, start_response)
    
    # For direct access
    handler = application
    
    print("✅ INDEX: Aplicación lista para Vercel")
    
except Exception as e:
    print(f"❌ INDEX: Error crítico: {e}")
    import traceback
    traceback.print_exc()
    raise

# For direct import/testing
if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))