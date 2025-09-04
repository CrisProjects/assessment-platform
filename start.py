#!/usr/bin/env python3
"""
Starter simple para Railway - Flask directo
"""
import os
import sys

# Agregar directorio actual al path
sys.path.insert(0, os.path.dirname(__file__))

if __name__ == "__main__":
    # Importar y ejecutar
    from wsgi_production import app, PORT
    print(f"🚀 Iniciando servidor en puerto {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
