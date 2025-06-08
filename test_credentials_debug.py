#!/usr/bin/env python3
"""
Script para verificar las credenciales paso a paso
"""

import requests
import json

def test_credentials():
    print("🔐 Verificando credenciales paso a paso...")
    print("=" * 50)
    
    backend_url = "https://assessment-platform-1nuo.onrender.com"
    frontend_url = "https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app"
    
    # Credenciales a probar
    credentials = [
        ("admin", "admin123"),
        ("admin", "Admin123"),  # Por si es case sensitive
        ("Admin", "admin123"),
    ]
    
    for username, password in credentials:
        print(f"\n🧪 Probando: {username} / {password}")
        
        # Test directo en backend
        try:
            response = requests.post(f"{backend_url}/login", 
                                   data={'username': username, 'password': password},
                                   allow_redirects=False)  # No seguir redirects
            
            print(f"   Status Code: {response.status_code}")
            
            if response.status_code == 302:
                print("   ✅ LOGIN EXITOSO - Redirect al dashboard")
                location = response.headers.get('location', '')
                print(f"   📍 Redirect a: {location}")
                
                # Verificar si podemos acceder al dashboard con las cookies
                cookies = response.cookies
                dashboard_response = requests.get(f"{backend_url}/dashboard", 
                                                cookies=cookies, 
                                                allow_redirects=False)
                
                if dashboard_response.status_code == 200:
                    print("   ✅ Dashboard accesible con las cookies de sesión")
                else:
                    print(f"   ⚠️  Dashboard response: {dashboard_response.status_code}")
                
                # Test con CORS headers (como lo haría el frontend)
                cors_response = requests.post(f"{backend_url}/login",
                                            data={'username': username, 'password': password},
                                            headers={'Origin': frontend_url},
                                            allow_redirects=False)
                
                print(f"   CORS Test Status: {cors_response.status_code}")
                cors_headers = cors_response.headers.get('Access-Control-Allow-Origin', 'None')
                print(f"   CORS Headers: {cors_headers}")
                
                if cors_response.status_code == 302:
                    print("   ✅ Login funciona con CORS desde frontend")
                    return True
                    
            elif response.status_code == 400:
                print("   ❌ Credenciales incorrectas")
            else:
                print(f"   ⚠️  Respuesta inesperada: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n🔍 Verificando estado de la base de datos...")
    
    # Test para ver si hay usuarios en la BD
    try:
        # Primero hacer login exitoso para obtener sesión
        login_response = requests.post(f"{backend_url}/login", 
                                     data={'username': 'admin', 'password': 'admin123'},
                                     allow_redirects=False)
        
        if login_response.status_code == 302:
            cookies = login_response.cookies
            
            # Acceder al dashboard para ver si hay datos
            dashboard_response = requests.get(f"{backend_url}/dashboard", cookies=cookies)
            
            if "admin" in dashboard_response.text.lower():
                print("   ✅ Usuario admin existe en la base de datos")
            
            if "bienvenido" in dashboard_response.text.lower():
                print("   ✅ Página de dashboard carga correctamente")
                
        print("\n📱 Para probar desde el frontend:")
        print(f"   1. Ir a: {frontend_url}")
        print("   2. Usar credenciales: admin / admin123")
        print("   3. El login debería funcionar ahora")
            
    except Exception as e:
        print(f"   ❌ Error verificando BD: {e}")
    
    return False

if __name__ == "__main__":
    test_credentials()
