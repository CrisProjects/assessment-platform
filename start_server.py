#!/usr/bin/env python3
"""
Servidor estable para Assessment Platform
Sin reloader problemático
"""

import os
import sys
from pathlib import Path

# Añadir el directorio actual al path
sys.path.insert(0, str(Path(__file__).parent))

# Configurar variables de entorno
os.environ['FLASK_DEBUG'] = '0'
os.environ['FLASK_ENV'] = 'development'

# Importar y ejecutar la aplicación
from app import app

if __name__ == '__main__':
    print("🚀 Assessment Platform - Servidor Estable")
    print("📡 Ejecutándose en: http://127.0.0.1:5002")
    print("🔧 Modo: Desarrollo sin reloader")
    print("⚡ Presiona Ctrl+C para detener")
    print("-" * 50)
    
    try:
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
