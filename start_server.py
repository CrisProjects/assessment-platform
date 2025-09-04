#!/usr/bin/env python3
import os
import sys

# Configurar Flask
os.environ['FLASK_APP'] = 'app.py'
os.environ['FLASK_ENV'] = 'development'

if __name__ == '__main__':
    print("🚀 Iniciando servidor Flask...")
    print("📍 Puerto: 5002")
    print("🌐 URL: http://localhost:5002")
    print("🔑 Dashboard Coachee: http://localhost:5002/coachee-dashboard")
    print("⚠️  Usa Ctrl+C para detener")
    print("-" * 50)
    
    # Importar la app después de configurar el entorno
    from app import app, auto_initialize_database
    
    # Inicializar la base de datos
    with app.app_context():
        auto_initialize_database()
    
    # Ejecutar la aplicación SIN debug para evitar auto-reloads problemáticos
    try:
        print("🚫 Modo debug DESACTIVADO para mayor estabilidad")
        app.run(
            host='0.0.0.0',
            port=5002,
            debug=False,
            use_reloader=False,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n👋 Servidor detenido por el usuario")
    except Exception as e:
        print(f"❌ Error: {e}")
