#!/usr/bin/env python3
"""
Diagnóstico de emergencia para Render - se ejecutará como un endpoint
"""
import os
import sys
from flask import Flask

# App de diagnóstico simple
diagnostic_app = Flask(__name__)

@diagnostic_app.route('/')
def diagnostic_root():
    """Endpoint de diagnóstico principal"""
    try:
        # Información del sistema
        info = {
            "status": "DIAGNOSTIC_APP_WORKING",
            "python_version": sys.version,
            "working_directory": os.getcwd(),
            "port": os.environ.get('PORT', 'NOT_SET'),
            "environment_vars": {k: v for k, v in os.environ.items() if 'RENDER' in k or 'PORT' in k},
            "files_in_directory": sorted(os.listdir('.')),
            "can_import_main_app": False,
            "main_app_routes": []
        }
        
        # Intentar importar la app principal
        try:
            from app_complete import app
            info["can_import_main_app"] = True
            info["main_app_routes"] = [rule.rule for rule in app.url_map.iter_rules()]
            info["main_app_object"] = str(app)
        except Exception as e:
            info["main_app_import_error"] = str(e)
        
        return info
        
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e),
            "python_version": sys.version,
            "working_directory": os.getcwd()
        }

@diagnostic_app.route('/test-simple')
def test_simple():
    """Endpoint simple de prueba"""
    return {"message": "Diagnostic app working", "endpoint": "/test-simple"}

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    diagnostic_app.run(host='0.0.0.0', port=port, debug=True)
