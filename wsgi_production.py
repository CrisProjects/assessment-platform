#!/usr/bin/env python3
"""
WSGI entry point optimizado para Render
Incluye inicialización completa de base de datos con preguntas de asertividad
Versión mejorada con mejor manejo de errores y logging
"""
import os
import sys
import logging

# Configurar logging para production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the complete application with proper error handling
try:
    logger.info("🔄 RENDER DEPLOY: Importando aplicación...")
    from app_complete import app
    logger.info("✅ RENDER DEPLOY: App importada exitosamente")
    
    # Initialize database in production with complete setup
    logger.info("🔄 RENDER DEPLOY: Inicializando base de datos completa...")
    with app.app_context():
        from app_complete import db, auto_initialize_database
        try:
            # Force create all tables first
            db.create_all()
            logger.info("✅ RENDER DEPLOY: Tablas creadas")
            
            # Run complete auto-initialization
            init_success = auto_initialize_database()
            if init_success:
                logger.info("✅ RENDER DEPLOY: Base de datos inicializada completamente")
                
                # Verify critical data exists
                from app_complete import Question, Assessment, User
                question_count = Question.query.count()
                assessment_count = Assessment.query.count()
                admin_exists = User.query.filter_by(role='platform_admin').first() is not None
                
                logger.info(f"📊 RENDER DEPLOY: Verificación - Questions: {question_count}, Assessments: {assessment_count}, Admin: {admin_exists}")
                
                if question_count >= 10 and assessment_count >= 1 and admin_exists:
                    logger.info("🎉 RENDER DEPLOY: Validación exitosa - Sistema listo")
                else:
                    logger.warning("⚠️ RENDER DEPLOY: Warning - Algunos datos podrían estar incompletos")
            else:
                logger.warning("⚠️ RENDER DEPLOY: Warning durante inicialización de DB")
                
        except Exception as e:
            logger.error(f"❌ RENDER DEPLOY: Error durante inicialización de DB: {e}")
            logger.info("🔄 RENDER DEPLOY: Intentando recuperación...")
            
            # Try fallback initialization
            try:
                db.create_all()
                logger.info("✅ RENDER DEPLOY: Recuperación - Tablas creadas")
            except Exception as fallback_err:
                logger.error(f"❌ RENDER DEPLOY: Error en recuperación: {fallback_err}")
    
except Exception as e:
    logger.error(f"❌ RENDER DEPLOY: Error crítico importando app: {e}")
    
    # Create a minimal fallback app with detailed error info
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    @app.route('/health')
    @app.route('/status')
    def health():
        return jsonify({
            'status': 'error',
            'message': 'Application failed to initialize properly',
            'error': str(e),
            'deploy_stage': 'app_import',
            'timestamp': os.environ.get('RENDER_BUILD_TIMESTAMP', 'unknown')
        }), 500
    
    @app.route('/debug')
    def debug():
        return jsonify({
            'python_version': sys.version,
            'working_directory': os.getcwd(),
            'files_in_dir': os.listdir('.'),
            'environment_vars': {k: v for k, v in os.environ.items() if 'SECRET' not in k and 'PASSWORD' not in k},
            'sys_path': sys.path[:5]  # First 5 entries
        })

# This is what Render will import
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    logger.info(f"🚀 RENDER DEPLOY: Iniciando servidor en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
