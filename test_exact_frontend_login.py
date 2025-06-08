#!/usr/bin/env python3
"""
Test simulando exactamente la llamada que hace el frontend React
"""

import requests
import json

def test_frontend_login():
    print("🌐 Simulando login desde el frontend React...")
    print("=" * 50)
    
    backend_url = "https://assessment-platform-1nuo.onrender.com"
    frontend_url = "https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app"
    
    # Crear sesión con headers como lo hace axios
    session = requests.Session()
    session.headers.update({
        'Origin': frontend_url,
        'Referer': frontend_url,
        'User-Agent': 'Mozilla/5.0 (Frontend Test)',
        'Accept': 'application/json, text/plain, */*'
    })
    
    print("📝 Preparando FormData como lo hace el frontend...")
    
    # Simular FormData del frontend
    form_data = {
        'username': 'admin',
        'password': 'admin123'
    }
    
    print(f"   Usuario: {form_data['username']}")
    print(f"   Contraseña: {'*' * len(form_data['password'])}")
    
    try:
        print("\n🚀 Enviando request POST /login...")
        
        # Exactamente como lo hace axios
        response = session.post(
            f"{backend_url}/login",
            data=form_data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            allow_redirects=False,  # Como maxRedirects: 0
            timeout=30
        )
        
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        
        # Verificar CORS
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
        
        print(f"\n🔍 CORS Headers:")
        print(f"   Access-Control-Allow-Origin: {cors_origin}")
        print(f"   Access-Control-Allow-Credentials: {cors_credentials}")
        
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            print(f"\n✅ LOGIN EXITOSO!")
            print(f"   Redirect a: {location}")
            
            # Verificar cookies
            cookies = response.cookies
            print(f"   Cookies recibidas: {len(cookies)} cookies")
            for cookie in cookies:
                print(f"     - {cookie.name}: {cookie.value[:20]}...")
            
            # Test acceso al dashboard con cookies
            print(f"\n🔐 Probando acceso al dashboard con cookies...")
            dashboard_response = session.get(
                f"{backend_url}/dashboard",
                cookies=cookies,
                headers={'Origin': frontend_url}
            )
            
            if dashboard_response.status_code == 200:
                print("   ✅ Dashboard accesible - Sesión válida")
                
                # Probar API endpoints
                print(f"\n📡 Probando API endpoints...")
                
                api_response = session.get(
                    f"{backend_url}/api/assessments",
                    cookies=cookies,
                    headers={'Origin': frontend_url}
                )
                
                if api_response.status_code == 200:
                    data = api_response.json()
                    assessments = data.get('assessments', [])
                    print(f"   ✅ API /assessments: {len(assessments)} evaluaciones")
                else:
                    print(f"   ❌ API /assessments: Status {api_response.status_code}")
                    
            else:
                print(f"   ❌ Dashboard inaccesible: Status {dashboard_response.status_code}")
                
        elif response.status_code == 400:
            print(f"\n❌ LOGIN FALLIDO: Credenciales incorrectas")
            print(f"   Respuesta: {response.text}")
            
        else:
            print(f"\n⚠️  Status inesperado: {response.status_code}")
            print(f"   Respuesta: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error de conexión: {e}")
        
    print(f"\n📱 Para probar manualmente:")
    print(f"   1. Abrir: {frontend_url}")
    print(f"   2. Usar: admin / admin123")
    print(f"   3. Revisar Network tab en DevTools para ver errores")

if __name__ == "__main__":
    test_frontend_login()
