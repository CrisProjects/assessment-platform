#!/usr/bin/env python3
"""
Script para probar la corrección de la base de datos
"""
import requests
import time

def test_database_fix():
    """Probar que la base de datos se inicialice correctamente"""
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print("🧪 PROBANDO CORRECCIÓN DE BASE DE DATOS")
    print("=" * 50)
    
    # 1. Probar endpoint de salud
    print("1. Probando endpoint de salud...")
    try:
        response = requests.get(f"{base_url}/api/health", timeout=30)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # 2. Probar inicialización forzada
    print("\n2. Ejecutando inicialización forzada...")
    try:
        response = requests.post(f"{base_url}/api/force-init-db", timeout=30)
        print(f"   Status: {response.status_code}")
        data = response.json()
        print(f"   Tables created: {data.get('tables_created', [])}")
        print(f"   User table exists: {data.get('user_table_exists', False)}")
        print(f"   Admin created: {data.get('admin_user_created', False)}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # 3. Probar login con usuario admin
    print("\n3. Probando login con usuario admin...")
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
    
    # 4. Probar acceso a página de login (frontend)
    print("\n4. Probando acceso a página de login...")
    try:
        response = requests.get(f"{base_url}/login", timeout=30)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Página de login carga correctamente")
        else:
            print(f"   ❌ Error cargando página: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Pruebas completadas")

if __name__ == "__main__":
    test_database_fix()
