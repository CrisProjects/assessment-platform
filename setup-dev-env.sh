#!/bin/bash

# Script de configuración del entorno de desarrollo
# Usage: ./setup-dev-env.sh

set -e

echo "🚀 Configurando entorno de desarrollo para Assessment Platform..."

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes con colores
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si estamos en el directorio correcto
if [ ! -f "app_complete.py" ]; then
    print_error "Este script debe ejecutarse desde el directorio raíz del proyecto"
    exit 1
fi

# 1. Verificar Python
print_status "Verificando instalación de Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python encontrado: $PYTHON_VERSION"
else
    print_error "Python 3 no está instalado"
    exit 1
fi

# 2. Crear entorno virtual si no existe
if [ ! -d ".venv" ]; then
    print_status "Creando entorno virtual..."
    python3 -m venv .venv
    print_success "Entorno virtual creado"
else
    print_warning "Entorno virtual ya existe"
fi

# 3. Activar entorno virtual e instalar dependencias
print_status "Activando entorno virtual e instalando dependencias..."
source .venv/bin/activate

# Actualizar pip
python -m pip install --upgrade pip

# Instalar dependencias
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "Dependencias instaladas desde requirements.txt"
else
    print_warning "requirements.txt no encontrado, instalando dependencias básicas..."
    pip install flask flask-sqlalchemy flask-login flask-cors werkzeug python-dotenv
fi

# 4. Configurar archivo de entorno
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        print_success "Archivo .env creado desde .env.example"
        print_warning "Por favor, edita .env con tus configuraciones específicas"
    else
        print_warning "No se encontró .env.example, creando .env básico..."
        cat > .env << EOF
FLASK_APP=app_complete.py
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(16))')
DATABASE_URL=sqlite:///assessments.db
HOST=0.0.0.0
PORT=5002
EOF
        print_success "Archivo .env básico creado"
    fi
else
    print_warning "Archivo .env ya existe"
fi

# 5. Inicializar base de datos si no existe
if [ ! -f "assessments.db" ]; then
    print_status "Inicializando base de datos..."
    python init_complete_db.py
    print_success "Base de datos inicializada"
else
    print_warning "Base de datos ya existe"
fi

# 6. Crear directorios necesarios
print_status "Creando directorios necesarios..."
mkdir -p logs
mkdir -p instance
mkdir -p static/css
mkdir -p static/js
mkdir -p static/images
print_success "Directorios creados"

# 7. Verificar instalación
print_status "Verificando instalación..."
python -c "
try:
    import flask, flask_sqlalchemy, flask_login, flask_cors
    print('✅ Todas las dependencias principales están instaladas')
except ImportError as e:
    print(f'❌ Error en dependencias: {e}')
    exit(1)
"

print_success "¡Entorno de desarrollo configurado exitosamente!"
echo ""
echo "📋 Próximos pasos:"
echo "   1. source .venv/bin/activate  # Activar entorno virtual"
echo "   2. python app_complete.py     # Ejecutar la aplicación"
echo "   3. Abrir http://localhost:5002 en tu navegador"
echo ""
echo "🔧 Comandos útiles:"
echo "   ./run-dev.sh              # Ejecutar en modo desarrollo"
echo "   ./run-tests.sh            # Ejecutar tests"
echo "   deactivate                # Desactivar entorno virtual"
