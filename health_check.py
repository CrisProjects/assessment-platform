#!/usr/bin/env python3
"""
Health check endpoint para monitoreo en producción
Verifica el estado de la aplicación, base de datos y componentes críticos
"""
import os
import sys
from datetime import datetime

# Agregar directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_application_health():
    """Verificar el estado general de la aplicación"""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'checks': {},
        'version': '2.0.0'
    }
    
    try:
        # Verificar importación de la aplicación
        from app_complete import app, db
        health_status['checks']['app_import'] = 'ok'
        
        # Verificar configuración básica
        if app.config.get('SECRET_KEY'):
            health_status['checks']['secret_key'] = 'ok'
        else:
            health_status['checks']['secret_key'] = 'warning'
            
        # Verificar base de datos
        with app.app_context():
            try:
                from app_complete import User, Assessment, Question
                
                # Contar elementos críticos
                user_count = User.query.count()
                assessment_count = Assessment.query.count()
                question_count = Question.query.count()
                
                if user_count > 0 and assessment_count > 0 and question_count >= 10:
                    health_status['checks']['database'] = 'ok'
                    health_status['data'] = {
                        'users': user_count,
                        'assessments': assessment_count,
                        'questions': question_count
                    }
                else:
                    health_status['checks']['database'] = 'warning'
                    health_status['status'] = 'degraded'
                    
            except Exception as db_error:
                health_status['checks']['database'] = 'error'
                health_status['status'] = 'unhealthy'
                health_status['errors'] = [str(db_error)]
                
        # Verificar variables de entorno críticas
        env_checks = []
        if os.environ.get('FLASK_ENV'):
            env_checks.append('FLASK_ENV')
        if os.environ.get('SECRET_KEY') or app.config.get('SECRET_KEY'):
            env_checks.append('SECRET_KEY')
            
        health_status['checks']['environment'] = 'ok' if env_checks else 'warning'
        health_status['environment'] = {
            'flask_env': os.environ.get('FLASK_ENV', 'not_set'),
            'has_secret': bool(os.environ.get('SECRET_KEY')),
            'python_version': sys.version.split()[0]
        }
        
    except Exception as e:
        health_status['status'] = 'unhealthy'
        health_status['checks']['app_import'] = 'error'
        health_status['errors'] = [str(e)]
    
    return health_status

if __name__ == "__main__":
    health = check_application_health()
    
    print("🔍 HEALTH CHECK RESULTS:")
    print(f"Status: {health['status'].upper()}")
    print(f"Timestamp: {health['timestamp']}")
    
    for check, result in health['checks'].items():
        emoji = "✅" if result == 'ok' else "⚠️" if result == 'warning' else "❌"
        print(f"{emoji} {check}: {result}")
    
    if 'data' in health:
        print(f"\n📊 Database:")
        for key, value in health['data'].items():
            print(f"  - {key}: {value}")
    
    if 'environment' in health:
        print(f"\n🌍 Environment:")
        for key, value in health['environment'].items():
            print(f"  - {key}: {value}")
    
    if 'errors' in health:
        print(f"\n❌ Errors:")
        for error in health['errors']:
            print(f"  - {error}")
    
    # Exit code based on health status
    if health['status'] == 'healthy':
        sys.exit(0)
    elif health['status'] == 'degraded':
        sys.exit(1)
    else:
        sys.exit(2)
