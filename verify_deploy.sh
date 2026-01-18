#!/bin/bash
# Script para verificar que todos los cambios están listos para deploy

echo "🔍 VERIFICACIÓN DE DEPLOY - Assessment Platform"
echo "================================================"
echo ""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

# 1. Verificar estado de git
echo "📋 1. Verificando estado de Git..."
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${RED}❌ Hay cambios sin commitear${NC}"
    git status --short
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✅ Working tree limpio${NC}"
fi
echo ""

# 2. Verificar que estamos en la rama correcta
echo "📋 2. Verificando rama actual..."
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${YELLOW}⚠️  Estás en la rama: $CURRENT_BRANCH (no main)${NC}"
    WARNINGS=$((WARNINGS + 1))
else
    echo -e "${GREEN}✅ Rama: main${NC}"
fi
echo ""

# 3. Verificar sincronización con origin
echo "📋 3. Verificando sincronización con origin..."
git fetch origin main --quiet
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse @{u})
BASE=$(git merge-base @ @{u})

if [ "$LOCAL" = "$REMOTE" ]; then
    echo -e "${GREEN}✅ Local sincronizado con origin${NC}"
elif [ "$LOCAL" = "$BASE" ]; then
    echo -e "${RED}❌ Necesitas hacer git pull${NC}"
    ERRORS=$((ERRORS + 1))
elif [ "$REMOTE" = "$BASE" ]; then
    echo -e "${RED}❌ Hay commits locales sin pushear${NC}"
    echo "   Ejecuta: git push"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${RED}❌ Las ramas han divergido${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 4. Verificar últimos commits
echo "📋 4. Últimos 5 commits:"
git log --pretty=format:"   %h - %s (%cr)" -5
echo ""
echo ""

# 5. Verificar archivos críticos
echo "📋 5. Verificando archivos críticos para deploy..."
CRITICAL_FILES=(
    "app.py"
    "wsgi_production.py"
    "Procfile"
    "railway.toml"
    "requirements.txt"
    "templates/coach_feed.html"
    "templates/coach_dashboard_v2.html"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅${NC} $file"
    else
        echo -e "${RED}❌${NC} $file (no encontrado)"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# 6. Verificar configuración de Railway
echo "📋 6. Verificando configuración Railway..."
if [ -f "railway.toml" ]; then
    START_CMD=$(grep "startCommand" railway.toml | head -1)
    echo "   Start command: $START_CMD"
    
    if grep -q "wsgi_production.py" railway.toml; then
        echo -e "${GREEN}✅ Configurado para usar wsgi_production.py${NC}"
    else
        echo -e "${YELLOW}⚠️  No se encontró referencia a wsgi_production.py${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${RED}❌ railway.toml no encontrado${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 7. Verificar cache-busting en templates
echo "📋 7. Verificando cache-busting en templates..."
if grep -q "get_file_version" templates/coach_feed.html; then
    echo -e "${GREEN}✅ coach_feed.html tiene cache-busting${NC}"
else
    echo -e "${YELLOW}⚠️  coach_feed.html sin cache-busting${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "get_file_version" templates/coach_dashboard_v2.html; then
    echo -e "${GREEN}✅ coach_dashboard_v2.html tiene cache-busting${NC}"
else
    echo -e "${YELLOW}⚠️  coach_dashboard_v2.html sin cache-busting${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# 8. Verificar que el servidor local funciona
echo "📋 8. Verificando servidor local..."
if curl -s http://localhost:5002/api/status > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Servidor local respondiendo${NC}"
else
    echo -e "${YELLOW}⚠️  Servidor local no responde (puede estar apagado)${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Resumen
echo "================================================"
echo "📊 RESUMEN DE VERIFICACIÓN"
echo "================================================"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ TODO LISTO PARA DEPLOY${NC}"
    echo ""
    echo "Comandos para deploy:"
    echo "  1. git push (si no lo has hecho)"
    echo "  2. Railway detectará el cambio automáticamente"
    echo ""
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  HAY $WARNINGS ADVERTENCIA(S)${NC}"
    echo "   Puedes proceder con precaución"
    echo ""
    exit 0
else
    echo -e "${RED}❌ HAY $ERRORS ERROR(ES) QUE DEBES CORREGIR${NC}"
    echo ""
    exit 1
fi
