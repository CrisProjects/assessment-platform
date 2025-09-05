#!/bin/bash

# Script para probar endpoints administrativos en Railway
echo "🔧 TESTING RAILWAY ADMIN ENDPOINTS"
echo "================================="

RAILWAY_URL="https://assessment-platform-production.up.railway.app"
SECRET_KEY="${SECRET_FIX_KEY:-tu_clave_secreta}"

echo "📍 Railway URL: $RAILWAY_URL"
echo "🔑 Using SECRET_KEY: ${SECRET_KEY:0:10}..."
echo ""

# Test 1: Endpoint público de diagnóstico
echo "1️⃣ Testing public diagnosis endpoint..."
curl -X GET "$RAILWAY_URL/api/public/diagnose-coach-assignments" \
     -H "Content-Type: application/json" \
     -w "\nStatus: %{http_code}\n" \
     -s
echo ""
echo "----------------------------------------"

# Test 2: Endpoint admin de verificación (necesita SECRET_KEY)
echo "2️⃣ Testing admin check endpoint..."
curl -X GET "$RAILWAY_URL/api/admin/check-coach-assignments?secret_fix_key=$SECRET_KEY" \
     -H "Content-Type: application/json" \
     -w "\nStatus: %{http_code}\n" \
     -s
echo ""
echo "----------------------------------------"

# Test 3: Endpoint admin de corrección (necesita SECRET_KEY)
echo "3️⃣ Testing admin fix endpoint..."
echo "⚠️  Este endpoint APLICARÁ las correcciones automáticamente"
echo "    Descomenta la línea siguiente solo cuando estés listo:"
echo "    # curl -X POST \"$RAILWAY_URL/api/admin/fix-coach-assignments?secret_fix_key=$SECRET_KEY\" -H \"Content-Type: application/json\""
echo ""

echo "✅ Test completado"
echo ""
echo "🔧 Para ejecutar la corrección automática:"
echo "   export SECRET_FIX_KEY='tu_clave_secreta'"
echo "   ./test_railway_endpoints.sh"
