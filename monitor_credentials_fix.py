#!/usr/bin/env python3
"""
Monitoreo en tiempo real de la corrección de credenciales
"""
import requests
import time
import json
from datetime import datetime

def check_credentials_fix():
    """Verifica si las credenciales están funcionando"""
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print(f"🔍 MONITOREO DE CREDENCIALES - {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    
    # 1. Verificar endpoint de inicialización
    print("1. Verificando endpoint de inicialización...")
    try:
        response = requests.get(f"{base_url}/api/init-db", timeout=15)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Admin existe: {data.get('admin_exists', False)}")
            print(f"   ✅ Usuarios totales: {data.get('user_count', 0)}")
            print(f"   ✅ Inicialización: {data.get('initialization_result', False)}")
        else:
            print(f"   ❌ Error: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ Error de conexión: {e}")
    
    # 2. Probar login
    print("\n2. Probando login admin/admin123...")
    try:
        login_data = {"username": "admin", "password": "admin123"}
        response = requests.post(
            f"{base_url}/api/login",
            json=login_data,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"   ✅ LOGIN EXITOSO!")
                print(f"   ✅ Usuario: {data['user']['username']}")
                print(f"   ✅ Admin: {data['user']['is_admin']}")
                return True
            else:
                print(f"   ❌ Login falló: {data.get('error', 'Unknown error')}")
        else:
            content_type = response.headers.get('content-type', '')
            if 'json' in content_type:
                print(f"   ❌ Error JSON: {response.json()}")
            else:
                print(f"   ❌ Error HTML: {response.text[:100]}")
                
    except Exception as e:
        print(f"   ❌ Error de conexión: {e}")
    
    # 3. Probar registro de usuario nuevo
    print("\n3. Probando registro de usuario nuevo...")
    try:
        register_data = {
            "username": f"testuser_{int(time.time())}",
            "password": "testpass123"
        }
        response = requests.post(
            f"{base_url}/api/register",
            json=register_data,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"   ✅ REGISTRO EXITOSO!")
                print(f"   ✅ Nuevo usuario: {data['user']['username']}")
            else:
                print(f"   ❌ Registro falló: {data.get('error', 'Unknown error')}")
        else:
            print(f"   ❌ Error: {response.text[:100]}")
            
    except Exception as e:
        print(f"   ❌ Error de conexión: {e}")
    
    return False

def monitor_deployment():
    """Monitorea el deployment hasta que las credenciales funcionen"""
    print("🚀 MONITOREO DE CORRECCIÓN DE CREDENCIALES")
    print("=" * 60)
    print("Esperando a que Render despliegue las correcciones...")
    print("Esto puede tomar 3-10 minutos.\n")
    
    attempts = 0
    max_attempts = 20  # 10 minutos
    
    while attempts < max_attempts:
        attempts += 1
        
        print(f"\n🔄 Intento {attempts}/{max_attempts}")
        
        if check_credentials_fix():
            print("\n" + "=" * 60)
            print("🎉 ¡CREDENCIALES FUNCIONANDO!")
            print("✅ admin/admin123 está operativo")
            print("✅ La plataforma está lista para usar")
            print(f"🌐 URL: https://assessment-platform-1nuo.onrender.com")
            return True
        
        if attempts < max_attempts:
            print(f"\n⏳ Esperando 30 segundos antes del siguiente intento...")
            time.sleep(30)
    
    print("\n" + "=" * 60)
    print("⚠️ TIMEOUT ALCANZADO")
    print("Las credenciales aún no funcionan después de 10 minutos.")
    print("Esto podría indicar un problema más profundo.")
    return False

if __name__ == "__main__":
    success = monitor_deployment()
    
    if not success:
        print("\n🔧 PRÓXIMOS PASOS RECOMENDADOS:")
        print("1. Verificar logs de Render para errores específicos")
        print("2. Probar manualmente: https://assessment-platform-1nuo.onrender.com/api/init-db")
        print("3. Considerar redeploy manual desde el dashboard de Render")
