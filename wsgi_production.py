#!/usr/bin/env python3
"""
WSGI entry point para Railway - Máxima compatibilidad
"""
import os
import sys

# Configurar path
sys.path.insert(0, os.path.dirname(__file__))

# Configurar variables de entorno básicas
os.environ.setdefault('FLASK_ENV', 'production')

try:
    # Importar app
    from app import app
    
    # Configurar app para producción
    app.config.update({
        'ENV': 'production',
        'DEBUG': False,
        'TESTING': False
    })
    
    # Variable para gunicorn
    application = app
    
    # Inicializar en contexto de app si es necesario
    if not hasattr(app, '_initialized'):
        try:
            with app.app_context():
                from app import auto_initialize_database
                auto_initialize_database()
                app._initialized = True
        except Exception:
            # No fallar por problemas de inicialización
            pass
    
    # Ejecutar directamente si es llamado como script
    if __name__ == "__main__":
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=False)
        
except Exception as e:
    print(f"Error crítico en WSGI: {e}")
    sys.exit(1)