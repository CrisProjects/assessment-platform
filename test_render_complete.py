#!/usr/bin/env python3
"""
Test completo de funcionalidad de endpoints en Render
"""
import requests
import json

def test_render_endpoints():
    base_url = "https://assessment-platform-1uot.onrender.com"
    
    print("🧪 PRUEBA COMPLETA DE ENDPOINTS EN RENDER")
    print("=" * 50)
    
    # Lista de endpoints para probar
    endpoints = [
        "/",
        "/api/health", 
        "/api/init-db",
        "/api/force-init-db",
        "/health",
        "/status"
    ]
    
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        print(f"\n🔗 Probando: {endpoint}")
        
        try:
            response = requests.get(url, timeout=15)
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"   ✅ JSON Response: {json.dumps(data, indent=2, ensure_ascii=False)[:200]}...")
                except:
                    print(f"   ✅ Text Response: {response.text[:100]}...")
            else:
                print(f"   ❌ Error: {response.text[:100]}")
                
        except Exception as e:
            print(f"   ❌ Exception: {str(e)}")
            
        print("-" * 30)

if __name__ == "__main__":
    test_render_endpoints()
