#!/usr/bin/env python3
"""
Inicialización completa de base de datos para Railway
Script independiente para configurar la base de datos en producción
"""
import os
import sys

# Configurar variables de entorno para Railway
os.environ['RAILWAY'] = '1'
os.environ['PRODUCTION'] = '1'
os.environ['FLASK_ENV'] = 'production'

# Agregar directorio actual al path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def main():
    """Función principal de inicialización"""
    try:
        print("🚀 RAILWAY INIT: Iniciando configuración de base de datos...")
        
        # Importar la aplicación Flask
        from app_complete import app, db
        print("✅ RAILWAY INIT: App importada exitosamente")
        
        # Ejecutar inicialización en contexto de aplicación
        with app.app_context():
            print("🔄 RAILWAY INIT: Creando tablas...")
            db.create_all()
            print("✅ RAILWAY INIT: Tablas creadas")
            
            # Ejecutar auto-inicialización completa
            print("🔄 RAILWAY INIT: Ejecutando auto-inicialización...")
            from app_complete import auto_initialize_database
            
            success = auto_initialize_database()
            if success:
                print("✅ RAILWAY INIT: Base de datos inicializada completamente")
                
                # Verificar datos críticos
                from app_complete import Question, Assessment, User
                question_count = Question.query.count()
                assessment_count = Assessment.query.count()
                user_count = User.query.count()
                
                print(f"📊 RAILWAY INIT: Verificación final:")
                print(f"   - Preguntas: {question_count}")
                print(f"   - Assessments: {assessment_count}")
                print(f"   - Usuarios: {user_count}")
                
                if question_count >= 10 and assessment_count >= 1 and user_count >= 1:
                    print("🎉 RAILWAY INIT: ¡Inicialización exitosa! Sistema listo.")
                    return True
                else:
                    print("⚠️ RAILWAY INIT: Warning - Algunos datos podrían estar incompletos")
                    return False
            else:
                print("❌ RAILWAY INIT: Error durante auto-inicialización")
                return False
                
    except Exception as e:
        print(f"❌ RAILWAY INIT: Error crítico: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("✅ RAILWAY INIT: Script completado exitosamente")
        sys.exit(0)
    else:
        print("❌ RAILWAY INIT: Script falló")
        sys.exit(1)
