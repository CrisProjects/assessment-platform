#!/usr/bin/env python3
"""
WSGI entry point para Railway - Optimizado
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

# Verificar puerto de Railway
PORT = int(os.environ.get('PORT', 5000))
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
    
    # Verificar base de datos
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        logger.info(f"🗄️ RAILWAY: Conectando a PostgreSQL...")
        # Railway proporciona DATABASE_URL automáticamente
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace('postgres://', 'postgresql://', 1)
    else:
        logger.warning("⚠️ RAILWAY: No se encontró DATABASE_URL, usando SQLite")
    
    # Variable para gunicorn
    application = app
    
    # Inicializar base de datos en Railway
    if not hasattr(app, '_railway_initialized'):
        try:
            logger.info("🔧 RAILWAY: Inicializando base de datos...")
            
            # Usar timeout para evitar bloquear el startup
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("Inicialización de BD excedió timeout")
            
            # Dar 30 segundos máximo para inicialización
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)
            
            try:
                with app.app_context():
                    from app import auto_initialize_database
                    auto_initialize_database()
                    app._railway_initialized = True
                    logger.info("✅ RAILWAY: Base de datos inicializada correctamente")
            finally:
                signal.alarm(0)  # Cancelar alarma
                
        except TimeoutError:
            logger.error("⏱️ RAILWAY: Timeout en inicialización de BD (continuando de todos modos)")
            app._railway_initialized = True  # Marcar como inicializada para no reintentar
        except Exception as init_error:
            logger.error(f"❌ RAILWAY: Error inicializando base de datos: {init_error}")
            logger.error("⚠️ RAILWAY: Continuando de todos modos, puede que necesites ejecutar /api/nuclear-reset-users")
            app._railway_initialized = True  # Marcar como inicializada para no reintentar
    
    logger.info("✅ RAILWAY: WSGI configurado correctamente")

except Exception as e:
    logger.error(f"❌ RAILWAY: Error crítico en WSGI: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Ejecutar directamente cuando se llama desde Railway
if __name__ == "__main__":
    logger.info(f"🚀 RAILWAY: Iniciando servidor directo en puerto {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)