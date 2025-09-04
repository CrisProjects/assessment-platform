#!/usr/bin/env python3

import os
import sys
from app import app, auto_initialize_database

if __name__ == '__main__':
    print("🚀 Iniciando servidor...")
    with app.app_context():
        auto_initialize_database()
    
    port = int(os.environ.get('PORT', 5002))
    print(f"🌐 Servidor disponible en: http://localhost:{port}")
    print("📱 Para acceder al dashboard del coachee: http://localhost:{port}/coachee_dashboard")
    print("⚠️  Usa Ctrl+C para detener el servidor")
    
    try:
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n👋 Servidor detenido")
        sys.exit(0)
