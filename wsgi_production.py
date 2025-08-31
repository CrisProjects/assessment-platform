#!/usr/bin/env python3
"""
WSGI entry point para producción en Railway
"""
import os
import logging
import time

# Configuración de logging para producción
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

# Esperar un momento adicional para PostgreSQL
time.sleep(2)

# Importar la aplicación
from app import app, auto_initialize_database

# Intentar la inicialización con reintentos para PostgreSQL
max_retries = 3
for attempt in range(max_retries):
    try:
        logging.info(f"🔄 WSGI: Intento de inicialización {attempt + 1}/{max_retries}")
        with app.app_context():
            auto_initialize_database()
        logging.info("✅ WSGI: Inicialización completada exitosamente")
        break
    except Exception as e:
        logging.error(f"❌ WSGI: Error en intento {attempt + 1}: {e}")
        if attempt < max_retries - 1:
            logging.info("⏳ WSGI: Esperando antes del siguiente intento...")
            time.sleep(3)
        else:
            logging.error("💥 WSGI: Todos los intentos fallaron")

# Variable requerida por gunicorn
application = app

# Configuración específica para Railway
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)