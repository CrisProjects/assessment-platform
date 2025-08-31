#!/usr/bin/env python3
"""
WSGI entry point para producción en Railway
"""
import os
import logging
from app import app

# Configuración de logging para producción
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

# Variable requerida por gunicorn
application = app

# Configuración específica para Railway
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)