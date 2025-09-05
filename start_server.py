#!/usr/bin/env python3
import os
import sys
import subprocess

# Configurar Flask
os.environ['FLASK_APP'] = 'app.py'
os.environ['FLASK_ENV'] = 'development'

# Puerto fijo para evitar cambios
FIXED_PORT = 5002

def check_and_kill_port():
    """Ejecuta predev.py para limpiar el puerto antes de iniciar"""
    try:
        print("🧹 Limpiando puerto antes de iniciar...")
        subprocess.run([sys.executable, 'predev.py'], check=True)
    except subprocess.CalledProcessError:
        print("⚠️  Error ejecutando predev.py, continuando...")
    except FileNotFoundError:
        print("⚠️  predev.py no encontrado, continuando...")

if __name__ == '__main__':
    # Limpiar puerto antes de iniciar
    check_and_kill_port()
    
    print("🚀 Iniciando servidor Flask...")
    print(f"📍 Puerto FIJO: {FIXED_PORT}")
    print(f"🌐 URL: http://localhost:{FIXED_PORT}")
    print(f"🔑 Dashboard Coachee: http://localhost:{FIXED_PORT}/coachee-dashboard")
    print("⚠️  Usa Ctrl+C para detener")
    print("🔒 Puerto fijo configurado - NO cambiará automáticamente")
    print("-" * 50)
    
    # Importar la app después de configurar el entorno
    from app import app, auto_initialize_database
    
    # Inicializar la base de datos
    with app.app_context():
        auto_initialize_database()
    
    # Ejecutar la aplicación SIN debug para evitar auto-reloads problemáticos
    try:
        print("🚫 Modo debug DESACTIVADO para mayor estabilidad")
        print("🚫 Auto-reload DESACTIVADO para evitar desconexiones")
        app.run(
            host='0.0.0.0',
            port=FIXED_PORT,
            debug=False,
            use_reloader=False,  # Evita auto-reload problemático
            threaded=True,       # Mejor manejo de conexiones concurrentes
        )
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ Error: Puerto {FIXED_PORT} ya está en uso")
            print("💡 Ejecuta 'python predev.py' para limpiar el puerto")
            print("💡 O usa 'python predev.py --check' para verificar qué lo usa")
        else:
            print(f"❌ Error del servidor: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        sys.exit(1)
