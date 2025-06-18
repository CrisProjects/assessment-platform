#!/usr/bin/env python3
"""
Script de diagnóstico específico para verificar el estado de Render
"""

import requests
import json
import time
from datetime import datetime

def test_render_status():
    """Diagnóstico completo del estado de Render"""
    base_url = "https://assessment-platform-1uot.onrender.com"
    
    print(f"🔍 DIAGNÓSTICO RENDER - {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    
    # Test con headers detallados
    try:
        response = requests.get(base_url, timeout=15)
        print(f"📊 Status Code: {response.status_code}")
        print(f"📋 Headers: {dict(response.headers)}")
        print(f"📄 Content: {response.text[:500]}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"✅ JSON Response: {json.dumps(data, indent=2)}")
                return True, data
            except:
                print("⚠️ Response is not JSON")
                
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    return False, None

def test_api_endpoints():
    """Probar endpoints específicos"""
    base_url = "https://assessment-platform-1uot.onrender.com"
    endpoints = [
        "/api/init-db",
        "/api/force-init-db", 
        "/api/health",
        "/status"
    ]
    
    print(f"\n🧪 PROBANDO ENDPOINTS API")
    print("-" * 40)
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=10)
            print(f"{endpoint}: {response.status_code}")
            if response.status_code == 200:
                print(f"  ✅ Response: {response.text[:100]}...")
            else:
                print(f"  ❌ Error: {response.text[:100]}")
        except Exception as e:
            print(f"{endpoint}: ❌ {str(e)}")

if __name__ == "__main__":
    test_render_status()
    test_api_endpoints()
