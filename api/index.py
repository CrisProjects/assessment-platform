#!/usr/bin/env python3
"""
Handler principal para Vercel - Configuración simplificada
Este archivo debe estar en la raíz del proyecto
"""
import os
import sys

# Configurar variables de entorno ANTES de importar Flask
os.environ['VERCEL'] = '1'
os.environ['PRODUCTION'] = '1'
os.environ['FLASK_ENV'] = 'production'

# Agregar directorio actual al path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

print(f"🔍 VERCEL: Working directory: {current_dir}")
print(f"🔍 VERCEL: Python path: {sys.path[:3]}")

try:
    # Importar Flask app
    print("🔄 VERCEL: Importando app_complete...")
    from app_complete import app
    print("✅ VERCEL: App importada exitosamente")
    
    # Inicializar DB solo si es necesario
    with app.app_context():
        try:
            print("🔄 VERCEL: Verificando base de datos...")
            from app_complete import db, User
            
            # Quick check si la DB ya está inicializada
            user_count = User.query.count()
            print(f"✅ VERCEL: DB verificada. Usuarios: {user_count}")
            
            if user_count == 0:
                print("🔄 VERCEL: Inicializando DB por primera vez...")
                from app_complete import auto_initialize_database
                auto_initialize_database()
                print("✅ VERCEL: DB inicializada")
            
        except Exception as db_error:
            print(f"⚠️ VERCEL: DB warning: {db_error}")
    
    print("🎉 VERCEL: Handler listo")
    
except Exception as e:
    print(f"❌ VERCEL: Error crítico: {e}")
    import traceback
    traceback.print_exc()
    
    # Crear una app de emergencia
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    @app.route('/<path:path>')
    def emergency_handler(path=''):
        return jsonify({
            'error': 'Aplicación en modo de emergencia',
            'details': str(e),
            'path': path
        }), 500

# Handler para Vercel
def handler(request):
    """Entry point para Vercel"""
    try:
        return app(request.environ, lambda status, headers: None)
    except Exception as e:
        print(f"❌ HANDLER: Error en request: {e}")
        return f"Error: {e}", 500

# WSGI app para compatibilidad
def application(environ, start_response):
    """WSGI application"""
    try:
        return app.wsgi_app(environ, start_response)
    except Exception as e:
        print(f"❌ WSGI: Error: {e}")
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/plain')]
        start_response(status, headers)
        return [f"Error: {e}".encode()]

# Exportar para Vercel
app_handler = handler
