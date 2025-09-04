#!/bin/bash
# Comandos para gestión de puertos - Compatible con macOS/Linux/Windows

echo "🔧 Comandos para gestión del puerto 5002:"
echo ""

# macOS y Linux
echo "📱 macOS/Linux:"
echo "  Verificar puerto:     lsof -i :5002"
echo "  Matar puerto:         lsof -ti:5002 | xargs kill -9"
echo "  Ver procesos:         ps aux | grep python"
echo "  Matar Python:         pkill -f python"
echo ""

# Windows
echo "🪟 Windows:"
echo "  Verificar puerto:     netstat -ano | findstr :5002"
echo "  Matar por PID:        taskkill /F /PID <PID>"
echo "  Ver procesos Python:  tasklist | findstr python"
echo "  Matar Python:         taskkill /F /IM python.exe"
echo ""

echo "🚀 Scripts del proyecto:"
echo "  Limpiar puerto:       python predev.py"
echo "  Verificar estado:     python predev.py --check"
echo "  Iniciar servidor:     python start_server_stable.py"
echo ""

# Auto-ejecutar verificación si se pasa --check
if [ "$1" = "--check" ]; then
    echo "🔍 Verificando puerto 5002..."
    if command -v lsof > /dev/null; then
        lsof -i :5002 || echo "Puerto 5002 libre"
    else
        echo "Comando lsof no disponible en este sistema"
    fi
fi

# Auto-ejecutar limpieza si se pasa --kill
if [ "$1" = "--kill" ]; then
    echo "💀 Limpiando puerto 5002..."
    if command -v lsof > /dev/null; then
        lsof -ti:5002 | xargs kill -9 2>/dev/null && echo "Puerto limpio" || echo "Puerto ya estaba libre"
    else
        echo "Comando lsof no disponible en este sistema"
    fi
fi
