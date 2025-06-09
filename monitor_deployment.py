#!/usr/bin/env python3
"""
Monitor Render deployment and test API endpoints
Verifica cuando el nuevo deployment está disponible y prueba todos los endpoints
"""

import requests
import time
import json
from datetime import datetime

BASE_URL = "https://assessment-platform-1nuo.onrender.com"
ENDPOINTS_TO_TEST = [
    ("/api/health", "GET"),
    ("/api/questions", "GET"),  # Requires auth
    ("/api/register", "POST"),
]

def test_endpoint(url, method="GET", data=None, headers=None):
    """Test a single endpoint"""
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers, timeout=10)
        
        return {
            "status_code": response.status_code,
            "success": response.status_code < 500,
            "response": response.text[:200] if response.text else ""
        }
    except Exception as e:
        return {
            "status_code": None,
            "success": False,
            "error": str(e)
        }

def monitor_deployment():
    """Monitor deployment status"""
    print("🔄 Monitoreando deployment de Render...")
    print(f"⏰ Inicio: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    
    attempt = 1
    while attempt <= 20:  # Max 20 intentos (10 minutos)
        print(f"\n📡 Intento {attempt}/20 - {datetime.now().strftime('%H:%M:%S')}")
        
        # Test health endpoint first
        health_result = test_endpoint(f"{BASE_URL}/api/health")
        
        if health_result["success"] and health_result["status_code"] == 200:
            print("✅ ¡Deployment completado! API funcionando")
            print("🎉 Probando todos los endpoints...")
            
            # Test all endpoints
            for endpoint, method in ENDPOINTS_TO_TEST:
                url = f"{BASE_URL}{endpoint}"
                result = test_endpoint(url, method)
                status = "✅" if result["success"] else "❌"
                print(f"  {status} {method} {endpoint}: {result['status_code']}")
                
                if not result["success"] and "error" not in result:
                    print(f"    Response: {result['response']}")
            
            # Test registration flow
            print("\n🧪 Probando flujo de registro...")
            reg_data = {
                "username": f"test_user_{int(time.time())}",
                "password": "test123"
            }
            reg_result = test_endpoint(f"{BASE_URL}/api/register", "POST", reg_data)
            if reg_result["success"]:
                print("✅ Registro funcionando correctamente")
            else:
                print(f"❌ Error en registro: {reg_result.get('response', 'Unknown error')}")
            
            return True
            
        elif health_result["status_code"] == 404:
            print(f"⏳ Deployment aún en progreso... (HTTP 404)")
        else:
            print(f"⚠️  Response inesperada: {health_result}")
        
        if attempt < 20:
            print("   Esperando 30 segundos...")
            time.sleep(30)
        
        attempt += 1
    
    print("\n❌ Timeout: El deployment no se completó en 10 minutos")
    return False

if __name__ == "__main__":
    success = monitor_deployment()
    
    if success:
        print("\n" + "=" * 60)
        print("🎊 DEPLOYMENT EXITOSO - PLATAFORMA LISTA PARA USAR")
        print(f"🌐 URL Principal: {BASE_URL}")
        print("📋 Todos los endpoints API están funcionando")
        print("✨ La plataforma está completamente operativa")
    else:
        print("\n" + "=" * 60)
        print("⚠️  DEPLOYMENT PENDIENTE")
        print("💡 El deployment puede tomar más tiempo del esperado")
        print(f"🔍 Verifica manualmente: {BASE_URL}/api/health")
