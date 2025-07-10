#!/usr/bin/env python3
"""
WSGI entry point optimizado para Railway
Configuración específica para Railway deployment
"""
import os
import sys

# Configurar entorno Railway
os.environ['RAILWAY'] = '1'
os.environ['PRODUCTION'] = '1'
os.environ['FLASK_ENV'] = 'production'

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the complete application with proper error handling
try:
    print("🚄 RAILWAY DEPLOY: Importando aplicación...")
    from app_complete import app
    print("✅ RAILWAY DEPLOY: App importada exitosamente")
    
    # Initialize database in production with complete setup
    print("🚄 RAILWAY DEPLOY: Inicializando base de datos completa...")
    with app.app_context():
        from app_complete import db, auto_initialize_database
        try:
            # Force create all tables first
            db.create_all()
            print("✅ RAILWAY DEPLOY: Tablas creadas")
            
            # Run complete auto-initialization
            init_success = auto_initialize_database()
            if init_success:
                print("✅ RAILWAY DEPLOY: Base de datos inicializada completamente")
                
                # Verify critical data exists
                from app_complete import Question, Assessment, User
                question_count = Question.query.count()
                assessment_count = Assessment.query.count()
                admin_exists = User.query.filter_by(role='platform_admin').first() is not None
                
                print(f"📊 RAILWAY DEPLOY: Verificación - Questions: {question_count}, Assessments: {assessment_count}, Admin: {admin_exists}")
                
                if question_count >= 10 and assessment_count >= 1 and admin_exists:
                    print("🎉 RAILWAY DEPLOY: Validación exitosa - Sistema listo")
                else:
                    print("⚠️ RAILWAY DEPLOY: Warning - Algunos datos podrían estar incompletos")
            else:
                print("⚠️ RAILWAY DEPLOY: Warning durante inicialización de DB")
                
        except Exception as e:
            print(f"❌ RAILWAY DEPLOY: Error durante inicialización de DB: {e}")
            print("🔄 RAILWAY DEPLOY: Intentando recuperación...")
            
            # Fallback: Crear tables básicas si no existen
            try:
                db.create_all()
                print("✅ RAILWAY DEPLOY: Recuperación exitosa - tablas creadas")
            except Exception as recovery_error:
                print(f"❌ RAILWAY DEPLOY: Error en recuperación: {recovery_error}")
    
    print("🚄 RAILWAY DEPLOY: Aplicación lista para Railway")
    
except Exception as e:
    print(f"❌ RAILWAY DEPLOY: Error crítico durante importación: {e}")
    import traceback
    traceback.print_exc()
    
    # En caso de error crítico, crear una aplicación mínima
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    def emergency():
        return jsonify({
            'status': 'emergency_mode',
            'message': 'Aplicación en modo de emergencia',
            'error': str(e)
        })
    
    @app.route('/api/status')
    def status():
        return jsonify({
            'status': 'emergency_mode',
            'railway': True,
            'error': str(e)
        })
    
    print("🆘 RAILWAY DEPLOY: Modo de emergencia activado")

# Export for Railway/Gunicorn
application = app

if __name__ == "__main__":
    # For local testing
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
