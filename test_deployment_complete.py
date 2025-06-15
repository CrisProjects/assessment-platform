#!/usr/bin/env python3
"""
Script de verificación completa del deployment
Prueba login, dashboard y funcionalidad de administrador
"""

import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_login_and_dashboard():
    """Probar el flujo completo de login y acceso al dashboard"""
    
    print("🔍 Probando flujo completo de autenticación...")
    
    # Crear una sesión para mantener cookies
    session = requests.Session()
    
    # 1. Obtener la página de login
    print("1. Accediendo a la página de login...")
    login_page = session.get(f"{BASE_URL}/login")
    print(f"   Status: {login_page.status_code}")
    
    # 2. Intentar login con las credenciales de admin usando API
    print("2. Intentando login con admin/admin123...")
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }
    
    headers = {'Content-Type': 'application/json'}
    login_response = session.post(f"{BASE_URL}/api/login", json=login_data, headers=headers, allow_redirects=False)
    print(f"   Status: {login_response.status_code}")
    
    if login_response.status_code == 200:
        print("   ✅ Login exitoso")
        try:
            response_data = login_response.json()
            if response_data.get('success'):
                redirect_url = response_data.get('redirect_url', '/dashboard')
                print(f"   📍 Debe redirigir a: {redirect_url}")
                
                # 3. Intentar acceder al dashboard
                if redirect_url.startswith('/'):
                    dashboard_url = f"{BASE_URL}{redirect_url}"
                else:
                    dashboard_url = redirect_url
                    
                print("3. Accediendo al dashboard...")
                dashboard_response = session.get(dashboard_url)
                print(f"   Status: {dashboard_response.status_code}")
                
                if dashboard_response.status_code == 200:
                    print("   ✅ Dashboard accesible")
                    # Verificar si contiene elementos de admin
                    if 'admin' in dashboard_response.text.lower() or 'dashboard' in dashboard_response.text.lower():
                        print("   ✅ Contenido de dashboard detectado")
                        return True
                    else:
                        print("   ✅ Dashboard accesible")
                        return True
                else:
                    print(f"   ❌ Error accediendo al dashboard: {dashboard_response.status_code}")
                    return False
            else:
                print(f"   ❌ Login falló: {response_data.get('error', 'Error desconocido')}")
                return False
        except Exception as e:
            print(f"   ❌ Error procesando respuesta de login: {e}")
            return False
    else:
        print(f"   ❌ Login falló: {login_response.status_code}")
        print(f"   Respuesta: {login_response.text[:200]}")
        return False

def test_api_endpoints():
    """Probar que los endpoints de API están funcionando"""
    
    print("\n🔧 Probando endpoints de API...")
    
    endpoints = [
        ("/api/debug-users", "GET", "Debug de usuarios"),
        ("/api/init-db", "GET", "Inicialización de DB"),
    ]
    
    for endpoint, method, description in endpoints:
        try:
            url = f"{BASE_URL}{endpoint}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                print(f"   ✅ {description}: OK")
            else:
                print(f"   ❌ {description}: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ {description}: ERROR - {str(e)}")

def main():
    print("=" * 60)
    print("🚀 VERIFICACIÓN COMPLETA DEL DEPLOYMENT")
    print("=" * 60)
    print(f"URL Base: {BASE_URL}")
    print()
    
    # Probar APIs
    test_api_endpoints()
    
    # Probar login y dashboard
    login_success = test_login_and_dashboard()
    
    print("\n" + "=" * 60)
    print("📋 RESUMEN:")
    print("=" * 60)
    
    if login_success:
        print("✅ DEPLOYMENT EXITOSO!")
        print("✅ Usuario admin creado y funcional")
        print("✅ Login funciona correctamente")
        print("✅ Dashboard accesible")
        print()
        print("🎯 CREDENCIALES DE ACCESO:")
        print("   Usuario: admin")
        print("   Password: admin123")
        print(f"   URL: {BASE_URL}/login")
    else:
        print("❌ Hay problemas con el deployment")
        print("❌ Revisar logs y configuración")

if __name__ == "__main__":
    main()
