#!/usr/bin/env python3
"""
Script para diagnosticar problemas de dashboard en producción
"""

import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_coach_dashboard_flow():
    """Probar el flujo completo del dashboard del coach"""
    print("🔍 Diagnosticando dashboard del coach en producción...")
    
    # Crear sesión para mantener cookies
    session = requests.Session()
    
    # 1. Verificar servidor
    try:
        response = session.get(f"{BASE_URL}/api/health", timeout=10)
        if response.status_code == 200:
            print("✅ Servidor funcionando")
        else:
            print(f"⚠️ Servidor responde con: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error conectando: {e}")
        return False
    
    # 2. Hacer login como coach
    print("\n🔐 Intentando login como coach...")
    try:
        login_data = {
            "username": "coach_demo",
            "password": "coach123"
        }
        
        response = session.post(
            f"{BASE_URL}/api/login",
            json=login_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print(f"✅ Login exitoso: {result.get('user', {}).get('full_name')}")
                print(f"   Rol: {result.get('user', {}).get('role')}")
                print(f"   Redirect URL: {result.get('redirect_url')}")
            else:
                print(f"❌ Login falló: {result.get('error')}")
                return False
        else:
            print(f"❌ Error login HTTP {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"💥 Error en login: {e}")
        return False
    
    # 3. Acceder al dashboard del coach
    print("\n📊 Intentando acceder al dashboard del coach...")
    try:
        response = session.get(f"{BASE_URL}/coach-dashboard", timeout=10)
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Dashboard cargado exitosamente")
            print(f"   Tamaño de respuesta: {len(response.text)} caracteres")
            if "Dashboard Coach" in response.text:
                print("✅ Contenido del dashboard correcto")
            else:
                print("⚠️ Contenido del dashboard no reconocido")
        elif response.status_code == 500:
            print("❌ Error 500 en dashboard")
            print("   Primeras líneas del error:")
            print(response.text[:500])
        elif response.status_code == 302:
            print(f"🔄 Redirección: {response.headers.get('Location', 'No location header')}")
        else:
            print(f"⚠️ Respuesta inesperada: {response.status_code}")
            print(response.text[:200])
            
    except Exception as e:
        print(f"💥 Error accediendo al dashboard: {e}")
        return False
    
    # 4. Probar APIs del dashboard
    print("\n🔗 Probando APIs del dashboard...")
    api_endpoints = [
        "/api/coach/my-coachees",
        "/api/coach/dashboard-stats"
    ]
    
    for endpoint in api_endpoints:
        try:
            response = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {endpoint}: OK ({len(str(data))} chars)")
            else:
                print(f"❌ {endpoint}: HTTP {response.status_code}")
        except Exception as e:
            print(f"💥 {endpoint}: Error {e}")
    
    return True

if __name__ == '__main__':
    success = test_coach_dashboard_flow()
    print(f"\n{'🎉 Diagnóstico completado' if success else '💥 Diagnóstico falló'}")
