#!/usr/bin/env python3
"""
WSGI entry point para Railway - Optimizado
Updated: 2025-11-17 - Added TestPersonal module support
"""
import os
import sys
import logging

# Configurar path
sys.path.insert(0, os.path.dirname(__file__))

# Configurar logging para Railway
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurar variables de entorno para Railway
os.environ.setdefault('FLASK_ENV', 'production')
os.environ.setdefault('FLASK_DEBUG', 'False')

# Verificar puerto de Railway (Railway asigna dinámicamente el puerto)
PORT = int(os.environ.get('PORT', 8080))
logger.info(f"🚀 RAILWAY: Configurando puerto {PORT}")

try:
    # Importar app
    logger.info("📦 RAILWAY: Importando aplicación Flask...")
    from app import app
    
    # Configurar app para producción
    app.config.update({
        'ENV': 'production',
        'DEBUG': False,
        'TESTING': False,
        'SQLALCHEMY_ECHO': False
    })
    
    # Configurar PostgreSQL en Railway
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Railway usa postgres://, pero SQLAlchemy necesita postgresql://
        fixed_url = database_url.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = fixed_url
        logger.info(f"🗄️ RAILWAY: Conectando a PostgreSQL...")
        logger.info(f"📊 DATABASE_URL detectada: {database_url[:20]}...")
    else:
        logger.warning("⚠️ RAILWAY: No se encontró DATABASE_URL, usando SQLite local")
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assessments.db'
    
    # Variable para gunicorn
    application = app
    
    logger.info("✅ RAILWAY: WSGI configurado correctamente")
    logger.info("📋 RAILWAY: La inicialización de DB se hará en el endpoint /health")

except Exception as e:
    logger.error(f"❌ RAILWAY: Error crítico en WSGI: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Ejecutar directamente cuando se llama desde Railway
if __name__ == "__main__":
    logger.info(f"🚀 RAILWAY: Iniciando servidor directo en puerto {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)