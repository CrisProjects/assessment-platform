#!/usr/bin/env python3
"""
Script para probar y diagnosticar problemas de credenciales
"""
import requests
import json

def test_render_credentials():
    """Prueba las credenciales en Render"""
    url = "https://assessment-platform-1nuo.onrender.com"
    
    print("🔍 DIAGNÓSTICO DE CREDENCIALES - RENDER")
    print("=" * 50)
    
    # 1. Probar inicialización de BD
    print("1. Probando inicialización de base de datos...")
    try:
        init_response = requests.post(f"{url}/api/init-db", timeout=30)
        print(f"   Status: {init_response.status_code}")
        if init_response.status_code == 200:
            print(f"   Respuesta: {init_response.json()}")
        else:
            print(f"   Error: {init_response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 2. Probar login
    print("\n2. Probando login con admin/admin123...")
    login_data = {"username": "admin", "password": "admin123"}
    
    try:
        login_response = requests.post(
            f"{url}/api/login",
            json=login_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        print(f"   Status: {login_response.status_code}")
        print(f"   Content-Type: {login_response.headers.get('content-type', 'unknown')}")
        
        if 'application/json' in login_response.headers.get('content-type', ''):
            print(f"   JSON Response: {login_response.json()}")
        else:
            print(f"   HTML Response (primeros 200 chars): {login_response.text[:200]}")
            
    except Exception as e:
        print(f"   Error: {e}")
    
    # 3. Probar registro
    print("\n3. Probando registro de nuevo usuario...")
    register_data = {"username": "testuser", "password": "testpass123"}
    
    try:
        register_response = requests.post(
            f"{url}/api/register",
            json=register_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        print(f"   Status: {register_response.status_code}")
        if register_response.status_code == 200:
            print(f"   Respuesta: {register_response.json()}")
        else:
            print(f"   Error: {register_response.text[:200]}")
            
    except Exception as e:
        print(f"   Error: {e}")

def test_vercel_credentials():
    """Prueba las credenciales en Vercel"""
    # Aquí puedes agregar la URL actual de Vercel si está disponible
    print("\n🌐 DIAGNÓSTICO DE CREDENCIALES - VERCEL")
    print("=" * 50)
    print("   Vercel frontend está usando HTML estático")
    print("   Se conecta al backend de Render para autenticación")

if __name__ == "__main__":
    test_render_credentials()
    test_vercel_credentials()
    
    print("\n📋 RESUMEN:")
    print("- Si la inicialización falla, hay un problema con la BD")
    print("- Si el login devuelve HTML en lugar de JSON, hay un error interno")
    print("- Si el registro funciona, el problema es específico con las credenciales admin")
    print("\n🔧 SOLUCIONES:")
    print("1. Ejecutar inicialización manual: POST /api/init-db")
    print("2. Verificar logs de Render para errores específicos")
    print("3. Probar con usuario recién registrado")
