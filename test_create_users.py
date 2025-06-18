#!/usr/bin/env python3
"""
Usar endpoint existente para crear usuarios
"""
import requests

def create_users_with_existing_endpoint():
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print("👥 Intentando crear usuarios con endpoint existente...")
    
    # Primero probar inicialización
    print("\n1. Inicializando base de datos...")
    try:
        response = requests.post(f"{base_url}/api/init-db", timeout=30)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Crear usuarios
    print("\n2. Creando usuarios por defecto...")
    try:
        response = requests.post(f"{base_url}/api/create-users", timeout=30)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Intentar login después de crear usuarios
    print("\n3. Probando login después de crear usuarios...")
    try:
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        response = requests.post(f"{base_url}/api/login", json=login_data, timeout=30)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Login exitoso!")
            print(f"   Usuario: {data.get('user', {}).get('username')}")
            print(f"   Rol: {data.get('user', {}).get('role')}")
        else:
            print(f"   ❌ Login falló: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    create_users_with_existing_endpoint()
