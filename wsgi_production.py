#!/usr/bin/env python3
"""
WSGI entry point para producción en Railway - Versión Simplificada
"""
import os
import logging
import time

# Configuración de logging para producción
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

logger = logging.getLogger(__name__)

# Importar la aplicación primero
try:
    logger.info("🔄 WSGI: Importando aplicación...")
    from app import app
    logger.info("✅ WSGI: Aplicación importada exitosamente")
except Exception as e:
    logger.error(f"❌ WSGI: Error importando aplicación: {e}")
    raise

# Variable requerida por gunicorn (debe estar antes de cualquier inicialización)
application = app

# Intentar la inicialización después de definir application
try:
    logger.info("🔄 WSGI: Iniciando inicialización de base de datos...")
    with app.app_context():
        from app import auto_initialize_database
        auto_initialize_database()
    logger.info("✅ WSGI: Inicialización de base de datos completada")
except Exception as e:
    logger.error(f"⚠️ WSGI: Error en inicialización de BD (continuando): {e}")
    # No fallar el deployment por problemas de inicialización

# Configuración específica para Railway
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)