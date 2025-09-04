#!/bin/bash
# Quick Start Script para Assessment Platform LOCAL
# Compatible con macOS/Linux

echo "🚀 Assessment Platform - Quick Start LOCAL"
echo "=========================================="

# Verificar si estamos en el directorio correcto
if [ ! -f "app.py" ]; then
    echo "❌ Error: Ejecuta este script desde el directorio del proyecto"
    exit 1
fi

# Función para matar procesos en el puerto
kill_port() {
    echo "🧹 Limpiando puerto 5002..."
    if command -v lsof > /dev/null; then
        lsof -ti:5002 | xargs kill -9 2>/dev/null && echo "✅ Puerto limpio" || echo "✅ Puerto ya estaba libre"
    else
        echo "⚠️  lsof no disponible, intentando con Python..."
        python3 predev.py 2>/dev/null || echo "❌ No se pudo limpiar el puerto"
    fi
}

# Verificar Python
if ! command -v python3 > /dev/null; then
    echo "❌ Error: Python3 no está instalado"
    exit 1
fi

# Verificar dependencias
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: requirements.txt no encontrado"
    exit 1
fi

echo "🔍 Verificando dependencias..."
python3 -c "import flask" 2>/dev/null || {
    echo "📦 Instalando dependencias..."
    pip3 install -r requirements.txt
}

# Limpiar puerto
kill_port

# Esperar un momento
sleep 1

# Iniciar servidor
echo "🚀 Iniciando servidor LOCAL..."
echo "📍 URL: http://localhost:5002"
echo "🔑 Dashboard: http://localhost:5002/coachee-dashboard"
echo "⚠️  Presiona Ctrl+C para detener"
echo ""

# Ejecutar servidor estable
python3 start_server_stable.py
