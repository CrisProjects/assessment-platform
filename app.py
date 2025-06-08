#!/usr/bin/env python3
"""
Punto de entrada principal para la aplicación de evaluación de asertividad
Importa y ejecuta la aplicación completa desde app_complete.py
"""

# Importar la aplicación completa
from app_complete import app

# Configuración adicional si es necesaria
if __name__ == '__main__':
    # Solo para desarrollo local
    app.run(debug=True, host='0.0.0.0', port=5000)

# Para producción, WSGI importará 'app' directamente
