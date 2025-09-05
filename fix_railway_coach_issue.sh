#!/bin/bash

# Script para ejecutar corrección manual en Railway
echo "🔧 CORRECCIÓN MANUAL RAILWAY - Coach Dashboard Issue"
echo "=================================================="

RAILWAY_URL="https://assessment-platform-production.up.railway.app"

echo "📍 Railway URL: $RAILWAY_URL"
echo ""

echo "🔍 PASO 1: Verificar problema con endpoint debug..."
echo "Ejecutando: $RAILWAY_URL/api/debug/coach-coachee-problem"
curl -X GET "$RAILWAY_URL/api/debug/coach-coachee-problem" \
     -H "Content-Type: application/json" \
     -w "\nStatus: %{http_code}\n" \
     -s
echo ""
echo "----------------------------------------"

echo "🔧 PASO 2: Intentar corrección con endpoints administrativos..."
echo "⚠️  Necesitarás tu SECRET_FIX_KEY para esto"
echo ""

# Función para pedir la clave
read -p "🔑 Ingresa tu SECRET_FIX_KEY (o presiona Enter para omitir): " secret_key

if [ ! -z "$secret_key" ]; then
    echo "🔍 Verificando asignaciones de coach..."
    curl -X GET "$RAILWAY_URL/api/admin/check-coach-assignments?secret_fix_key=$secret_key" \
         -H "Content-Type: application/json" \
         -w "\nStatus: %{http_code}\n" \
         -s
    echo ""
    echo "----------------------------------------"
    
    echo "🚨 ¿Deseas ejecutar la corrección automática? (esto modificará la base de datos)"
    read -p "Escribe 'SI' para continuar: " confirmation
    
    if [ "$confirmation" = "SI" ]; then
        echo "⚙️  Ejecutando corrección automática..."
        curl -X POST "$RAILWAY_URL/api/admin/fix-coach-assignments?secret_fix_key=$secret_key" \
             -H "Content-Type: application/json" \
             -w "\nStatus: %{http_code}\n" \
             -s
        echo ""
        echo "✅ Corrección completada"
    else
        echo "❌ Corrección cancelada por el usuario"
    fi
else
    echo "⏭️  Saltando corrección automática (no se proporcionó clave)"
fi

echo ""
echo "📋 RESUMEN:"
echo "1. Si el debug endpoint funcionó, revisa los 'problematic_cases'"
echo "2. Si los endpoints admin funcionaron, la corrección debería estar aplicada"
echo "3. Verifica el dashboard del coach nuevamente"
echo ""
echo "🔄 Si el problema persiste, puede ser necesario reiniciar Railway o verificar la caché"
