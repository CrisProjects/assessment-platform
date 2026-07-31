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
    
    # Ejecutar migraciones críticas al arrancar (ANTES de cualquier request)
    logger.info("🔧 RAILWAY: Ejecutando migraciones de schema...")
    try:
        with app.app_context():
            from app import db
            from sqlalchemy import text
            
            # Migraciones de columnas faltantes en tabla user
            migrations = [
                ("original_password", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS original_password VARCHAR(120)"),
                ("avatar_url", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500)"),
                ("coach_notes", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS coach_notes TEXT"),
                ("last_login", "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS last_login TIMESTAMP"),
            ]
            
            # Migraciones críticas para coach_community
            coach_community_migrations = [
                ("image_url", "ALTER TABLE coach_community ADD COLUMN IF NOT EXISTS image_url TEXT"),
                ("image_type", "ALTER TABLE coach_community ADD COLUMN IF NOT EXISTS image_type VARCHAR(20) DEFAULT 'catalog'"),
            ]
            
            migrations_applied = []
            for column_name, migration_sql in migrations:
                try:
                    db.session.execute(text(migration_sql))
                    db.session.commit()
                    migrations_applied.append(column_name)
                    logger.info(f"✅ RAILWAY: Migración user.{column_name} aplicada")
                except Exception as migration_error:
                    db.session.rollback()
                    logger.warning(f"⚠️ RAILWAY: Migración user.{column_name} ya existe o error: {migration_error}")
            
            # Ejecutar migraciones de coach_community
            for column_name, migration_sql in coach_community_migrations:
                try:
                    db.session.execute(text(migration_sql))
                    db.session.commit()
                    migrations_applied.append(f"coach_community.{column_name}")
                    logger.info(f"✅ RAILWAY: Migración coach_community.{column_name} aplicada")
                except Exception as migration_error:
                    db.session.rollback()
                    logger.warning(f"⚠️ RAILWAY: Migración coach_community.{column_name} ya existe o error: {migration_error}")
            
            # Migración: security_log heredado tiene "timestamp" NOT NULL que el
            # modelo actual no llena → bloqueaba TODOS los inserts de auditoría
            # (y con ello el lockout de cuentas). Se relaja la restricción.
            try:
                db.session.execute(text('ALTER TABLE security_log ALTER COLUMN "timestamp" DROP NOT NULL'))
                db.session.commit()
                logger.info("✅ RAILWAY: security_log.timestamp ahora es NULLABLE")
            except Exception as sec_error:
                db.session.rollback()
                logger.warning(f"⚠️ RAILWAY: security_log.timestamp ya migrado o no existe: {sec_error}")

            # Migración de datos: renombrar la evaluación "DISC" → "Mapa Conductual"
            try:
                db.session.execute(text("UPDATE assessment SET title='Evaluación de Mapa Conductual' WHERE title='Evaluación DISC de Personalidad'"))
                db.session.commit()
                logger.info("✅ RAILWAY: Evaluación renombrada a 'Mapa Conductual'")
            except Exception as rename_error:
                db.session.rollback()
                logger.warning(f"⚠️ RAILWAY: Rename 'Mapa Conductual' ya aplicado o error: {rename_error}")

            if migrations_applied:
                logger.info(f"✅ RAILWAY: {len(migrations_applied)} migraciones aplicadas: {migrations_applied}")
            else:
                logger.info("✅ RAILWAY: Todas las columnas ya existen")
                
            # Crear tablas faltantes
            db.create_all()
            logger.info("✅ RAILWAY: Tablas verificadas/creadas")
            
    except Exception as migration_error:
        logger.error(f"❌ RAILWAY: Error en migraciones: {migration_error}")
        # Continuar de todas formas - la app debe arrancar
    
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