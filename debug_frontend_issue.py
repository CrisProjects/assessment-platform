#!/usr/bin/env python3
"""
Simulación exacta del frontend para detectar el problema
"""

import requests
import json

def test_frontend_simulation():
    """Simula exactamente la request que hace el frontend"""
    print("🔍 Simulando request exacta del frontend...")
    
    # Configuración exacta del frontend
    url = "https://assessment-platform-1nuo.onrender.com/api/login"
    headers = {
        'Content-Type': 'application/json',
        'Origin': 'https://assessment-platform-747h43vee-cris-projects-92f3df55.vercel.app',
        'Referer': 'https://assessment-platform-747h43vee-cris-projects-92f3df55.vercel.app/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    }
    
    data = {
        "username": "admin",
        "password": "admin123"
    }
    
    try:
        # Crear sesión para manejar cookies como lo hace el navegador
        session = requests.Session()
        
        print(f"📡 POST {url}")
        print(f"Headers: {headers}")
        print(f"Data: {data}")
        
        response = session.post(url, json=data, headers=headers, timeout=10)
        
        print(f"\n📨 Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            try:
                json_response = response.json()
                print(f"\n✅ JSON Response: {json_response}")
                
                if json_response.get('success'):
                    print("🎉 ¡Login exitoso en simulación!")
                    return True
                else:
                    print("❌ Login falló según respuesta JSON")
                    return False
            except json.JSONDecodeError:
                print("❌ Respuesta no es JSON válido")
                return False
        else:
            print(f"❌ Status code no exitoso: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error en simulación: {e}")
        return False

def test_options_preflight():
    """Prueba la request OPTIONS de preflight CORS"""
    print("\n🌐 Probando preflight CORS OPTIONS...")
    
    url = "https://assessment-platform-1nuo.onrender.com/api/login"
    headers = {
        'Origin': 'https://assessment-platform-747h43vee-cris-projects-92f3df55.vercel.app',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type'
    }
    
    try:
        response = requests.options(url, headers=headers, timeout=10)
        
        print(f"OPTIONS Status: {response.status_code}")
        print(f"CORS Headers: {dict(response.headers)}")
        
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
            'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
        }
        
        print(f"Relevant CORS Headers: {cors_headers}")
        
        if response.status_code in [200, 204]:
            print("✅ Preflight CORS exitoso")
            return True
        else:
            print(f"❌ Preflight CORS falló: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error en preflight: {e}")
        return False

def main():
    print("🔧 DIAGNÓSTICO DETALLADO - Frontend vs Backend")
    print("=" * 60)
    
    success1 = test_options_preflight()
    success2 = test_frontend_simulation()
    
    print("\n" + "=" * 60)
    print(f"📊 RESULTADO DEL DIAGNÓSTICO:")
    print(f"  - Preflight CORS: {'✅' if success1 else '❌'}")
    print(f"  - Simulación Frontend: {'✅' if success2 else '❌'}")
    
    if success1 and success2:
        print("\n🤔 El backend funciona correctamente.")
        print("   El problema puede estar en:")
        print("   1. Configuración de Vercel")
        print("   2. Variables de entorno del frontend")
        print("   3. Caché del navegador")
        print("   4. Manejo de errores en el frontend")
    else:
        print("\n❌ Hay problemas específicos que resolver.")

if __name__ == "__main__":
    main()
