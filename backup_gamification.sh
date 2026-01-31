#!/bin/bash

# ============================================
# Script de Backup - Sistema de Gamificación
# Fecha: 2026-01-31
# ============================================

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="backups/gamification"
DB_NAME="instacoach_db"  # Ajustar según tu BD

# Crear directorio de backups
mkdir -p "$BACKUP_DIR"

echo "🔄 Iniciando backup de seguridad..."
echo "Timestamp: $TIMESTAMP"
echo ""

# 1. Backup de Base de Datos
echo "📦 Backup de Base de Datos..."
if command -v mysqldump &> /dev/null; then
    mysqldump -u root -p "$DB_NAME" > "$BACKUP_DIR/db_backup_$TIMESTAMP.sql"
    echo "✅ BD respaldada: $BACKUP_DIR/db_backup_$TIMESTAMP.sql"
else
    echo "⚠️  mysqldump no encontrado. Backup manual necesario."
fi
echo ""

# 2. Backup de app.py
echo "📦 Backup de app.py..."
if [ -f "app.py" ]; then
    cp app.py "$BACKUP_DIR/app_backup_$TIMESTAMP.py"
    echo "✅ app.py respaldado: $BACKUP_DIR/app_backup_$TIMESTAMP.py"
else
    echo "⚠️  app.py no encontrado en el directorio actual"
fi
echo ""

# 3. Backup de templates críticos
echo "📦 Backup de templates..."
mkdir -p "$BACKUP_DIR/templates"
if [ -d "templates" ]; then
    cp templates/coach_dashboard*.html "$BACKUP_DIR/templates/" 2>/dev/null
    cp templates/coachee_dashboard*.html "$BACKUP_DIR/templates/" 2>/dev/null
    echo "✅ Templates respaldados"
else
    echo "⚠️  Directorio templates no encontrado"
fi
echo ""

# 4. Crear archivo de información
cat > "$BACKUP_DIR/backup_info_$TIMESTAMP.txt" << EOF
Backup de Sistema de Gamificación
==================================
Fecha: $(date)
Timestamp: $TIMESTAMP

Archivos incluidos:
- Base de datos: db_backup_$TIMESTAMP.sql
- Archivo principal: app_backup_$TIMESTAMP.py
- Templates: templates/

Estado del sistema antes del backup:
- Git branch: $(git branch --show-current 2>/dev/null || echo "N/A")
- Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo "N/A")

Instrucciones de rollback:
1. Restaurar BD: mysql -u root -p $DB_NAME < db_backup_$TIMESTAMP.sql
2. Restaurar app.py: cp app_backup_$TIMESTAMP.py ../app.py
3. Restaurar templates: cp templates/* ../../templates/
EOF

echo "📝 Información del backup guardada"
echo ""

# 5. Listar backups
echo "📋 Backups disponibles:"
ls -lh "$BACKUP_DIR" | tail -n 10
echo ""

echo "✅ Backup completado exitosamente!"
echo ""
echo "📍 Ubicación: $BACKUP_DIR"
echo ""
echo "⚠️  IMPORTANTE: Si algo sale mal, usa estos archivos para restaurar."
