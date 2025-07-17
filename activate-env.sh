#!/bin/bash

# Script para configurar correctamente el entorno virtual
# Uso: source activate-env.sh

echo "🔧 Configurando entorno virtual limpio..."

# Desactivar conda si está activo
if [[ "$CONDA_DEFAULT_ENV" != "" ]]; then
    echo "📦 Desactivando entorno conda: $CONDA_DEFAULT_ENV"
    conda deactivate
fi

# Desactivar cualquier entorno virtual previo
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "🐍 Desactivando entorno virtual previo: $VIRTUAL_ENV"
    deactivate
fi

# Verificar que existe el entorno virtual del proyecto
if [ ! -d ".venv" ]; then
    echo "❌ No se encontró .venv. Creando entorno virtual..."
    python3 -m venv .venv
    echo "✅ Entorno virtual creado"
fi

# Activar el entorno virtual del proyecto
echo "🚀 Activando entorno virtual del proyecto..."
source .venv/bin/activate

# Verificar que todo está correcto
echo ""
echo "📋 Estado del entorno:"
echo "   Python: $(which python)"
echo "   Pip: $(which pip)"
echo "   Virtual Env: $VIRTUAL_ENV"
echo "   Conda Env: ${CONDA_DEFAULT_ENV:-'None'}"

# Verificar dependencias principales
python -c "
try:
    import flask
    print('   Flask: ✅ Instalado')
except ImportError:
    print('   Flask: ❌ No instalado')
    
try:
    import flask_sqlalchemy
    print('   SQLAlchemy: ✅ Instalado')
except ImportError:
    print('   SQLAlchemy: ❌ No instalado')
"

echo ""
echo "✅ Entorno configurado correctamente!"
echo "💡 Para desactivar: deactivate"
