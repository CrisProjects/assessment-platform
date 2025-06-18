#!/usr/bin/env python3
"""
Test rápido para probar endpoint de inicialización
"""
import requests

def test_init_endpoints():
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print("🔍 Verificando endpoints de inicialización...")
    
    # Probar endpoint normal de inicialización
    print("\n1. Probando /api/init-db...")
    try:
        response = requests.get(f"{base_url}/api/init-db", timeout=30)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Probar POST en lugar de GET para force-init
    print("\n2. Probando POST /api/force-init-db...")
    try:
        response = requests.post(f"{base_url}/api/force-init-db", timeout=30)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
        else:
            print(f"   Error Response: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Probar GET en force-init
    print("\n3. Probando GET /api/force-init-db...")
    try:
        response = requests.get(f"{base_url}/api/force-init-db", timeout=30)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
        else:
            print(f"   Error Response: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    test_init_endpoints()
