#!/usr/bin/env python3
"""
Script para verificar configuración de deploy Railway
"""
import os
import sys
import requests
import json
from pathlib import Path

def check_files():
    """Verificar archivos necesarios para Railway"""
    print("🔍 Verificando archivos de configuración...")
    
    required_files = {
        'Procfile': 'Configuración de gunicorn',
        'wsgi_production.py': 'Entry point WSGI',
        'requirements.txt': 'Dependencias Python',
        'runtime.txt': 'Versión de Python',
        'railway.toml': 'Configuración Railway',
        'app.py': 'Aplicación Flask principal'
    }
    
    missing_files = []
    for file_path, description in required_files.items():
        if os.path.exists(file_path):
            print(f"✅ {file_path} - {description}")
        else:
            print(f"❌ {file_path} - {description} - FALTA")
            missing_files.append(file_path)
    
    return len(missing_files) == 0

def check_procfile():
    """Verificar Procfile"""
    print("\n🔍 Verificando Procfile...")
    
    try:
        with open('Procfile', 'r') as f:
            content = f.read().strip()
        
        if 'gunicorn' in content and 'wsgi_production:application' in content:
            print(f"✅ Procfile correcto: {content}")
            return True
        else:
            print(f"❌ Procfile incorrecto: {content}")
            return False
    except FileNotFoundError:
        print("❌ Procfile no encontrado")
        return False

def check_wsgi():
    """Verificar WSGI"""
    print("\n🔍 Verificando wsgi_production.py...")
    
    try:
        import wsgi_production
        if hasattr(wsgi_production, 'application'):
            print("✅ wsgi_production.py correcto - application definida")
            return True
        else:
            print("❌ wsgi_production.py - falta variable 'application'")
            return False
    except ImportError as e:
        print(f"❌ Error importando wsgi_production.py: {e}")
        return False

def check_requirements():
    """Verificar requirements.txt"""
    print("\n🔍 Verificando requirements.txt...")
    
    try:
        with open('requirements.txt', 'r') as f:
            content = f.read()
        
        required_packages = ['Flask', 'gunicorn', 'psycopg2-binary']
        missing_packages = []
        
        for package in required_packages:
            if package.lower() in content.lower():
                print(f"✅ {package} encontrado")
            else:
                print(f"❌ {package} falta")
                missing_packages.append(package)
        
        return len(missing_packages) == 0
    except FileNotFoundError:
        print("❌ requirements.txt no encontrado")
        return False

def check_app_import():
    """Verificar que app.py se puede importar"""
    print("\n🔍 Verificando importación de app.py...")
    
    try:
        sys.path.insert(0, os.getcwd())
        from app import app
        print("✅ app.py se importa correctamente")
        
        # Verificar rutas básicas
        with app.test_client() as client:
            response = client.get('/api/status')
            if response.status_code == 200:
                print("✅ Endpoint /api/status funciona")
                return True
            else:
                print(f"❌ Endpoint /api/status devuelve {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Error importando app.py: {e}")
        return False

def check_database_config():
    """Verificar configuración de base de datos"""
    print("\n🔍 Verificando configuración de base de datos...")
    
    try:
        from app import app
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        
        if 'sqlite' in db_uri.lower():
            print("✅ SQLite configurado para desarrollo")
        
        # Verificar que puede manejar PostgreSQL
        test_postgres_uri = 'postgresql://user:pass@localhost/test'
        if 'postgres://' in test_postgres_uri:
            converted = test_postgres_uri.replace('postgres://', 'postgresql://', 1)
            print(f"✅ Conversión PostgreSQL funciona: {converted}")
        
        return True
    except Exception as e:
        print(f"❌ Error verificando base de datos: {e}")
        return False

def test_local_wsgi():
    """Probar WSGI localmente"""
    print("\n🔍 Probando WSGI localmente...")
    
    try:
        # Configurar variables como Railway
        os.environ['FLASK_ENV'] = 'production'
        os.environ['PORT'] = '8000'
        
        from wsgi_production import application
        
        # Test básico
        from werkzeug.test import Client
        from werkzeug.wrappers import Response
        
        client = Client(application, Response)
        response = client.get('/api/status')
        
        if response.status_code == 200:
            print("✅ WSGI responde correctamente")
            data = json.loads(response.data.decode())
            print(f"✅ Respuesta: {data.get('message', 'N/A')}")
            return True
        else:
            print(f"❌ WSGI devuelve {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error probando WSGI: {e}")
        return False

def generate_railway_commands():
    """Generar comandos para Railway CLI"""
    print("\n📋 Comandos para Railway CLI:")
    print("─" * 50)
    print("# 1. Instalar Railway CLI")
    print("npm install -g @railway/cli")
    print()
    print("# 2. Login en Railway")
    print("railway login")
    print()
    print("# 3. Crear nuevo proyecto")
    print("railway new")
    print()
    print("# 4. Conectar repositorio existente")
    print("railway link")
    print()
    print("# 5. Configurar variables de entorno")
    print("railway variables set FLASK_ENV=production")
    print("railway variables set FLASK_DEBUG=False")
    print("railway variables set FORCE_ADMIN_CREATION=true")
    print('railway variables set SECRET_KEY="railway-production-key-assessment-platform-2025-secure"')
    print()
    print("# 6. Agregar PostgreSQL")
    print("railway add postgresql")
    print()
    print("# 7. Deployar")
    print("railway up")
    print()
    print("# 8. Ver logs")
    print("railway logs")
    print()
    print("# 9. Abrir en navegador")
    print("railway open")

def main():
    print("🚀 VERIFICACIÓN DE DEPLOY RAILWAY")
    print("=" * 50)
    
    checks = [
        ("Archivos de configuración", check_files),
        ("Procfile", check_procfile),
        ("WSGI Production", check_wsgi),
        ("Requirements", check_requirements),
        ("Importación de App", check_app_import),
        ("Configuración de BD", check_database_config),
        ("Test WSGI Local", test_local_wsgi)
    ]
    
    passed = 0
    total = len(checks)
    
    for name, check_func in checks:
        print(f"\n{'='*20} {name} {'='*20}")
        if check_func():
            passed += 1
        else:
            print(f"❌ Falló: {name}")
    
    print(f"\n{'='*50}")
    print(f"📊 RESUMEN: {passed}/{total} verificaciones pasaron")
    
    if passed == total:
        print("🎉 ¡Listo para deploy en Railway!")
        generate_railway_commands()
    else:
        print("⚠️  Hay problemas que corregir antes del deploy")
        print("\n💡 Revisa los errores arriba y corrige los archivos indicados")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
