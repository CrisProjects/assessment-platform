#!/bin/bash
echo "🚀 Iniciando aplicación en Railway..."

# Crear admin si no existe
python create_admin.py

# Iniciar aplicación
exec gunicorn wsgi_production:application --bind 0.0.0.0:$PORT
