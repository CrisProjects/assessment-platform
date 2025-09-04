#!/bin/bash
echo "🚀 Iniciando aplicación en Railway..."

# Configurar variables de entorno por defecto
export FLASK_ENV=production
export PYTHONPATH="${PYTHONPATH}:."

# Ejecutar con gunicorn directamente
echo "🔥 Iniciando servidor con gunicorn..."
exec gunicorn wsgi_production:application \
  --bind 0.0.0.0:$PORT \
  --workers 1 \
  --worker-class sync \
  --timeout 120 \
  --keepalive 2 \
  --max-requests 1000 \
  --max-requests-jitter 100 \
  --log-level info \
  --access-logfile - \
  --error-logfile -
