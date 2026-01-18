#!/bin/bash

# 1. Limpiar variable de entorno de la sesión actual
unset DATABASE_URL

# 2. Limpiar historial de zsh (comandos con passwords)
# Nota: Esto solo limpia la sesión actual, el historial en disco persiste
echo "⚠️  Para limpiar el historial permanentemente:"
echo "   1. Abre ~/.zsh_history"
echo "   2. Busca y elimina las líneas con 'postgresql://postgres:JRsYnJTgjwUWwmsWqxBagMfzSecpbvWM'"
echo "   3. Guarda el archivo"
echo ""
echo "O ejecuta esto (CUIDADO: borra TODO el historial):"
echo "   > ~/.zsh_history"

# 3. Verificar que la variable se limpió
if [ -z "$DATABASE_URL" ]; then
    echo "✅ DATABASE_URL limpiada de la sesión actual"
else
    echo "⚠️  DATABASE_URL sigue definida: $DATABASE_URL"
fi

echo ""
echo "📋 RECOMENDACIONES DE SEGURIDAD:"
echo ""
echo "1. ✅ La conexión pública de Railway SOLO se usó desde tu IP"
echo "2. ⚠️  Considera rotar el password de PostgreSQL en Railway:"
echo "   - Railway Dashboard → Postgres → Variables → POSTGRES_PASSWORD"
echo "   - Genera nueva contraseña y redeploya tu app"
echo ""
echo "3. ✅ Para futuras migraciones, usa Railway CLI con 'railway run'"
echo "   - Evita exponer credenciales en terminal"
echo ""
echo "4. ⚠️  Desactiva Public Network si no la necesitas:"
echo "   - Railway Dashboard → Postgres → Settings"
echo "   - Esto reduce costos de egress"

