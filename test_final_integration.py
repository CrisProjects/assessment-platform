#!/usr/bin/env python3
"""
Prueba final de integración completa:
Frontend (Vercel) -> Backend (Render) con credenciales admin/admin123
"""

import requests
import json

def test_backend_api_login():
    """Prueba el endpoint /api/login del backend"""
    print("🔐 Probando endpoint /api/login del backend...")
    
    url = "https://assessment-platform-1nuo.onrender.com/api/login"
    data = {
        "username": "admin",
        "password": "admin123"
    }
    
    try:
        response = requests.post(url, json=data, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            json_response = response.json()
            if json_response.get('success'):
                print("✅ Login exitoso!")
                print(f"Usuario: {json_response['user']['username']}")
                print(f"Es admin: {json_response['user']['is_admin']}")
                return True
            else:
                print("❌ Login falló:", json_response.get('error', 'Error desconocido'))
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return False

def test_cors_headers():
    """Prueba que los headers CORS estén configurados correctamente"""
    print("\n🌐 Probando configuración CORS...")
    
    url = "https://assessment-platform-1nuo.onrender.com/api/login"
    headers = {
        'Origin': 'https://assessment-platform-747h43vee-cris-projects-92f3df55.vercel.app',
        'Content-Type': 'application/json'
    }
    data = {"username": "admin", "password": "admin123"}
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=10)
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
        }
        
        print(f"CORS Headers: {cors_headers}")
        
        if cors_headers['Access-Control-Allow-Origin']:
            print("✅ CORS configurado correctamente")
            return True
        else:
            print("❌ CORS no configurado")
            return False
            
    except Exception as e:
        print(f"❌ Error probando CORS: {e}")
        return False

def test_wrong_credentials():
    """Prueba que las credenciales incorrectas sean rechazadas"""
    print("\n🚫 Probando credenciales incorrectas...")
    
    url = "https://assessment-platform-1nuo.onrender.com/api/login"
    data = {
        "username": "admin",
        "password": "wrong_password"
    }
    
    try:
        response = requests.post(url, json=data, timeout=10)
        
        if response.status_code == 401:
            json_response = response.json()
            if not json_response.get('success'):
                print("✅ Credenciales incorrectas rechazadas correctamente")
                print(f"Error: {json_response.get('error')}")
                return True
        
        print(f"❌ Debería rechazar credenciales incorrectas. Status: {response.status_code}")
        return False
        
    except Exception as e:
        print(f"❌ Error probando credenciales incorrectas: {e}")
        return False

def main():
    print("🚀 PRUEBA FINAL DE INTEGRACIÓN")
    print("=" * 50)
    print("Frontend: https://assessment-platform-747h43vee-cris-projects-92f3df55.vercel.app")
    print("Backend: https://assessment-platform-1nuo.onrender.com")
    print("Credenciales: admin/admin123")
    print("=" * 50)
    
    tests = [
        test_backend_api_login,
        test_cors_headers,
        test_wrong_credentials
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n📊 RESULTADO FINAL: {passed}/{total} pruebas pasaron")
    
    if passed == total:
        print("🎉 ¡TODAS LAS PRUEBAS PASARON!")
        print("🔓 Los credenciales admin/admin123 deberían funcionar en el frontend de Vercel")
    else:
        print("❌ Algunas pruebas fallaron")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
