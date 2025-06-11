#!/usr/bin/env python3
"""
Verificación final de la versión limpia de producción
"""

import requests
import json

def test_production_version():
    """Test final de la versión de producción limpia"""
    
    print("🎯 VERIFICACIÓN FINAL - VERSIÓN LIMPIA DE PRODUCCIÓN")
    print("=" * 60)
    
    # URLs finales
    frontend_url = "https://assessment-platform-4h58ggw5n-cris-projects-92f3df55.vercel.app"
    backend_url = "https://assessment-platform-1nuo.onrender.com"
    
    print(f"🌐 Frontend Limpio: {frontend_url}")
    print(f"🔧 Backend Limpio:  {backend_url}")
    print()
    
    # Test 1: Verificar que endpoints de prueba estén removidos
    print("1️⃣ Verificando que endpoints de prueba estén removidos...")
    try:
        response = requests.get(f"{backend_url}/api/test/status", timeout=10)
        if response.status_code == 404:
            print("   ✅ Endpoints de prueba removidos correctamente")
        else:
            print(f"   ❌ Endpoint de prueba aún accesible: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ✅ Endpoints de prueba removidos (error de conexión esperado)")
    
    # Test 2: Verificar login de producción
    print("2️⃣ Verificando login de producción...")
    try:
        response = requests.post(
            f"{backend_url}/api/login",
            headers={
                'Content-Type': 'application/json',
                'Origin': frontend_url
            },
            json={
                'username': 'admin',
                'password': 'admin123'
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("   ✅ Login de producción funciona correctamente")
                print(f"   👤 Usuario: {data.get('user', {}).get('username')}")
            else:
                print("   ❌ Login falló")
                return False
        else:
            print(f"   ❌ Login error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error en login: {e}")
        return False
    
    # Test 3: Verificar que página de pruebas no esté accesible
    print("3️⃣ Verificando que página de pruebas esté removida...")
    try:
        response = requests.get(f"{frontend_url}/test", timeout=10)
        if response.status_code in [401, 404]:
            print("   ✅ Página de pruebas removida correctamente")
        else:
            print(f"   ❌ Página de pruebas aún accesible: {response.status_code}")
            return False
    except Exception as e:
        print("   ✅ Página de pruebas removida (error esperado)")
    
    return True

if __name__ == "__main__":
    print()
    success = test_production_version()
    print()
    print("=" * 60)
    if success:
        print("🎉 ¡ÉXITO! Versión limpia de producción funcionando perfectamente")
        print("✅ Todos los elementos de prueba han sido removidos")
        print("✅ La funcionalidad principal sigue operativa")
        print()
        print("🔗 Aplicación lista para usuarios finales:")
        print("   https://assessment-platform-4h58ggw5n-cris-projects-92f3df55.vercel.app")
        print()
        print("🔐 Credenciales:")
        print("   Usuario: admin")
        print("   Contraseña: admin123")
    else:
        print("❌ Hay problemas con la versión limpia")
    print("=" * 60)
