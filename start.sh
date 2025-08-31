#!/bin/bash
echo "🚀 Iniciando aplicación en Railway..."

# Esperar un momento para que PostgreSQL esté listo
echo "⏳ Esperando que la base de datos esté lista..."
sleep 5

# NO ejecutar create_admin.py - la inicialización se hace en wsgi_production.py
echo "🔥 Iniciando servidor con gunicorn (inicialización incluida)..."
exec gunicorn wsgi_production:application --bind 0.0.0.0:$PORT --log-level info --timeout 120
