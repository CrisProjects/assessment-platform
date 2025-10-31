#!/bin/bash
# Script para ejecutar migración automáticamente en Railway

echo "🔍 Verificando si necesita migración..."
python3 add_assessment_id_to_invitation.py

echo "✅ Migración completada, iniciando servidor..."
