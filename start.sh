#!/bin/bash
echo "🚀 Iniciando aplicación en Railway..."

# Esperar un momento para que PostgreSQL esté listo
echo "⏳ Esperando que la base de datos esté lista..."
sleep 3

# Crear admin si no existe (respaldo)
echo "👤 Ejecutando script de respaldo para usuarios..."
python create_admin.py

# Iniciar aplicación (la inicialización principal ocurre en wsgi_production.py)
echo "🔥 Iniciando servidor con gunicorn..."
exec gunicorn wsgi_production:application --bind 0.0.0.0:$PORT --log-level info
