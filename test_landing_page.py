#!/usr/bin/env python3
"""
Script de pruebas para la Landing Page
Verifica que todos los endpoints y assets estén funcionando correctamente
"""

import requests
import sys
import time
from urllib.parse import urljoin

def test_landing_page(base_url="http://127.0.0.1:5002"):
    """Prueba la landing page y sus componentes"""
    
    print("🧪 Iniciando pruebas de Landing Page...")
    print(f"🌐 URL Base: {base_url}")
    print("-" * 50)
    
    tests_passed = 0
    tests_total = 0
    
    def test_endpoint(path, expected_status=200, description=""):
        nonlocal tests_passed, tests_total
        tests_total += 1
        
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=10)
            
            if response.status_code == expected_status:
                print(f"✅ {description or path}: {response.status_code}")
                tests_passed += 1
                return True
            else:
                print(f"❌ {description or path}: {response.status_code} (esperado: {expected_status})")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ {description or path}: Error de conexión - {e}")
            return False
    
    # Pruebas de endpoints principales
    print("📍 Probando endpoints principales...")
    test_endpoint("/", description="Landing Page Principal")
    test_endpoint("/dashboard-selection", description="Dashboard Selection")
    test_endpoint("/login", description="Login Page")
    test_endpoint("/api/status", description="API Status")
    
    # Pruebas de assets estáticos
    print("\n🎨 Probando assets estáticos...")
    test_endpoint("/static/css/landing-enhancements.css", description="CSS Enhancements")
    test_endpoint("/static/js/landing-enhanced.js", description="JS Enhanced")
    test_endpoint("/static/images/hero-background.svg", description="Hero Background SVG")
    
    # Pruebas de contenido específico
    print("\n📄 Probando contenido de landing page...")
    try:
        response = requests.get(urljoin(base_url, "/"))
        if response.status_code == 200:
            content = response.text
            
            # Verificar elementos clave
            checks = [
                ("Transforma tu Asertividad", "Título principal"),
                ("Comenzar Evaluación", "CTA Button"),
                ("Assessment Platform", "Branding"),
                ("Inter", "Fuente Inter"),
                ("hero", "Hero Section"),
                ("features", "Features Section"),
                ("footer", "Footer Section")
            ]
            
            for check_text, description in checks:
                tests_total += 1
                if check_text in content:
                    print(f"✅ {description}: Presente")
                    tests_passed += 1
                else:
                    print(f"❌ {description}: Faltante")
        
    except Exception as e:
        print(f"❌ Error verificando contenido: {e}")
    
    # Verificar estructura de archivos locales
    print("\n📁 Verificando estructura de archivos...")
    import os
    
    files_to_check = [
        "templates/landing.html",
        "static/css/landing-enhancements.css", 
        "static/js/landing-enhanced.js",
        "static/images/hero-background.svg",
        "LANDING_PAGE.md"
    ]
    
    for file_path in files_to_check:
        tests_total += 1
        if os.path.exists(file_path):
            print(f"✅ {file_path}: Existe")
            tests_passed += 1
        else:
            print(f"❌ {file_path}: No encontrado")
    
    # Resumen final
    print("\n" + "="*50)
    print(f"📊 RESUMEN DE PRUEBAS")
    print(f"✅ Pasadas: {tests_passed}/{tests_total}")
    print(f"📈 Porcentaje éxito: {(tests_passed/tests_total)*100:.1f}%")
    
    if tests_passed == tests_total:
        print("🎉 ¡Todas las pruebas pasaron exitosamente!")
        print("🚀 La Landing Page está lista para producción")
        return True
    else:
        print("⚠️ Algunas pruebas fallaron. Revisar configuración.")
        return False

def wait_for_server(base_url="http://127.0.0.1:5002", max_attempts=30):
    """Espera a que el servidor esté disponible"""
    print("⏳ Esperando que el servidor esté disponible...")
    
    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{base_url}/api/status", timeout=2)
            if response.status_code == 200:
                print("✅ Servidor disponible!")
                return True
        except:
            pass
        
        time.sleep(1)
        print(f"⏳ Intento {attempt + 1}/{max_attempts}...")
    
    print("❌ Servidor no disponible después de esperar")
    return False

if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5002"
    
    print("🌟 Landing Page Test Suite")
    print("=" * 50)
    
    # Esperar a que el servidor esté listo
    if wait_for_server(base_url):
        # Ejecutar pruebas
        success = test_landing_page(base_url)
        sys.exit(0 if success else 1)
    else:
        print("❌ No se pudo conectar al servidor")
        sys.exit(1)
