#!/usr/bin/env python3
"""
Script para probar la funcionalidad completa de inicialización de base de datos una vez que el deployment esté activo
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "https://assessment-platform-1uot.onrender.com"

def test_app_status():
    """Verifica que la aplicación esté funcionando"""
    try:
        response = requests.get(BASE_URL, timeout=10)
        return response.status_code == 200, f"Status: {response.status_code}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def test_init_db_endpoint():
    """Prueba el endpoint /api/init-db"""
    print("\n🔄 Probando endpoint /api/init-db...")
    try:
        response = requests.get(f"{BASE_URL}/api/init-db", timeout=15)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Respuesta: {json.dumps(data, indent=2, ensure_ascii=False)}")
            return True, data
        else:
            print(f"   ❌ Error {response.status_code}: {response.text}")
            return False, None
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False, None

def test_force_init_db_endpoint():
    """Prueba el endpoint /api/force-init-db"""
    print("\n🚨 Probando endpoint /api/force-init-db...")
    try:
        # Probar GET primero
        response = requests.get(f"{BASE_URL}/api/force-init-db", timeout=20)
        print(f"   GET Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ GET Respuesta: {json.dumps(data, indent=2, ensure_ascii=False)}")
            
            # Ahora probar POST para forzar inicialización
            print("\n   🔧 Ejecutando POST para forzar inicialización...")
            post_response = requests.post(f"{BASE_URL}/api/force-init-db", timeout=30)
            print(f"   POST Status: {post_response.status_code}")
            
            if post_response.status_code == 200:
                post_data = post_response.json()
                print(f"   ✅ POST Respuesta: {json.dumps(post_data, indent=2, ensure_ascii=False)}")
                return True, post_data
            else:
                print(f"   ❌ POST Error {post_response.status_code}: {post_response.text}")
                return False, None
        else:
            print(f"   ❌ GET Error {response.status_code}: {response.text}")
            return False, None
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False, None

def verify_database_state():
    """Verifica el estado final de la base de datos"""
    print("\n📊 Verificando estado final de la base de datos...")
    try:
        response = requests.get(f"{BASE_URL}/api/init-db", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"   Usuario count: {data.get('user_count', 'N/A')}")
            print(f"   Admin existe: {data.get('admin_exists', 'N/A')}")
            print(f"   Tablas creadas: {data.get('tables_created', 'N/A')}")
            return True, data
        else:
            print(f"   ❌ Error verificando estado: {response.status_code}")
            return False, None
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False, None

def main():
    print("🧪 PRUEBA COMPLETA DE INICIALIZACIÓN DE BASE DE DATOS")
    print("=" * 60)
    print(f"🕒 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 URL Base: {BASE_URL}")
    
    # 1. Verificar que la app esté funcionando
    print("\n1️⃣ Verificando que la aplicación esté activa...")
    app_ok, app_msg = test_app_status()
    print(f"   {app_msg}")
    
    if not app_ok:
        print("\n❌ La aplicación no está respondiendo. Abortando pruebas.")
        return False
    
    # 2. Probar endpoint init-db normal
    print("\n2️⃣ Probando inicialización normal...")
    init_ok, init_data = test_init_db_endpoint()
    
    # 3. Probar endpoint force-init-db
    print("\n3️⃣ Probando inicialización forzada...")
    force_ok, force_data = test_force_init_db_endpoint()
    
    # 4. Verificar estado final
    print("\n4️⃣ Verificación final del estado...")
    final_ok, final_data = verify_database_state()
    
    # Resumen
    print("\n" + "=" * 60)
    print("📋 RESUMEN DE RESULTADOS:")
    print(f"   ✅ App funcionando: {'Sí' if app_ok else 'No'}")
    print(f"   ✅ Init-DB: {'Sí' if init_ok else 'No'}")
    print(f"   ✅ Force-Init-DB: {'Sí' if force_ok else 'No'}")
    print(f"   ✅ Verificación final: {'Sí' if final_ok else 'No'}")
    
    success = app_ok and (init_ok or force_ok) and final_ok
    
    if success:
        print("\n🎉 ¡TODAS LAS PRUEBAS EXITOSAS!")
        print("   La base de datos está inicializada y funcionando correctamente.")
        
        if final_data:
            user_count = final_data.get('user_count', 0)
            admin_exists = final_data.get('admin_exists', False)
            print(f"   👥 Usuarios en la base de datos: {user_count}")
            print(f"   👑 Admin existe: {'Sí' if admin_exists else 'No'}")
    else:
        print("\n❌ ALGUNAS PRUEBAS FALLARON")
        print("   Revisar los logs anteriores para más detalles.")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
