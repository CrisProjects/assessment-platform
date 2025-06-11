#!/usr/bin/env python3
"""
🚨 DIAGNÓSTICO EN VIVO: Problema al iniciar evaluación en Vercel
================================================================

Este script monitoreará específicamente el problema al hacer clic en 
"Comenzar Evaluación" en Vercel.
"""

import requests
import time
import json
from datetime import datetime

VERCEL_URL = "https://assessment-platform-final.vercel.app"
RENDER_API = "https://assessment-platform-1nuo.onrender.com"

def test_frontend_content():
    """Verificar contenido específico del frontend"""
    print("📋 DIAGNÓSTICO: Contenido del frontend")
    print("-" * 50)
    
    try:
        response = requests.get(VERCEL_URL, timeout=10)
        content = response.text
        
        print(f"Status: {response.status_code}")
        print(f"Content Length: {len(content)}")
        
        # Buscar elementos específicos
        checks = {
            "Formulario nombre": 'id="name"' in content,
            "Formulario email": 'id="email"' in content,
            "Formulario edad": 'id="age"' in content,
            "Formulario género": 'id="gender"' in content,
            "Botón Comenzar": 'Comenzar Evaluación' in content,
            "Función startAssessment": 'startAssessment' in content,
            "API_BASE_URL": 'API_BASE_URL' in content,
            "JavaScript presente": '<script>' in content
        }
        
        for check, result in checks.items():
            status = "✅" if result else "❌"
            print(f"   {status} {check}")
            
        # Verificar URL del API
        if 'API_BASE_URL' in content:
            import re
            api_match = re.search(r'API_BASE_URL\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if api_match:
                api_url = api_match.group(1)
                print(f"   🔗 API URL configurada: {api_url}")
                if api_url != RENDER_API:
                    print(f"   ⚠️  API URL no coincide con esperada: {RENDER_API}")
            
        return all(checks.values())
        
    except Exception as e:
        print(f"❌ Error verificando frontend: {e}")
        return False

def test_api_endpoints_individually():
    """Probar cada endpoint del API individualmente"""
    print("\n🔧 DIAGNÓSTICO: Endpoints del API")
    print("-" * 50)
    
    session = requests.Session()
    session.headers.update({
        'Origin': VERCEL_URL,
        'Referer': VERCEL_URL,
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    })
    
    endpoints = [
        ("/api/health", "GET", None),
        ("/api/login", "POST", {"username": "admin", "password": "admin123"}),
        ("/api/register", "POST", {"name": "Test", "email": "test@test.com", "age": 25, "gender": "masculino"}),
        ("/api/demographics", "POST", {"name": "Test", "email": "test@test.com", "age": 25, "gender": "masculino"}),
        ("/api/questions", "GET", None)
    ]
    
    results = {}
    
    for endpoint, method, data in endpoints:
        try:
            if method == "GET":
                response = session.get(f"{RENDER_API}{endpoint}", timeout=10)
            else:
                response = session.post(f"{RENDER_API}{endpoint}", json=data, timeout=10)
            
            results[endpoint] = {
                'status': response.status_code,
                'success': response.status_code == 200,
                'response_time': response.elapsed.total_seconds(),
                'error': None
            }
            
            status_icon = "✅" if response.status_code == 200 else "❌"
            print(f"   {status_icon} {method} {endpoint}: {response.status_code} ({response.elapsed.total_seconds():.2f}s)")
            
            if response.status_code != 200:
                print(f"      Error: {response.text[:100]}...")
                
        except Exception as e:
            results[endpoint] = {'status': 0, 'success': False, 'error': str(e)}
            print(f"   ❌ {method} {endpoint}: Error - {e}")
    
    return results

def test_cors_specifically():
    """Probar CORS específicamente para Vercel"""
    print("\n🔗 DIAGNÓSTICO: CORS específico")
    print("-" * 50)
    
    headers = {
        'Origin': VERCEL_URL,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type'
    }
    
    try:
        # Preflight request
        response = requests.options(f"{RENDER_API}/api/login", headers=headers, timeout=10)
        
        print(f"Preflight Status: {response.status_code}")
        print(f"Response Headers:")
        
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods', 
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Credentials'
        ]
        
        for header in cors_headers:
            value = response.headers.get(header, 'NO ENCONTRADO')
            print(f"   {header}: {value}")
        
        # Verificar si Vercel está permitido
        allow_origin = response.headers.get('Access-Control-Allow-Origin')
        vercel_allowed = allow_origin and (VERCEL_URL in allow_origin or allow_origin == '*')
        
        print(f"\n   🎯 Vercel permitido: {'✅ SÍ' if vercel_allowed else '❌ NO'}")
        
        return vercel_allowed
        
    except Exception as e:
        print(f"❌ Error en test CORS: {e}")
        return False

def simulate_button_click():
    """Simular exactamente lo que pasa cuando se hace clic en el botón"""
    print("\n🎯 DIAGNÓSTICO: Simulación de clic en botón")
    print("-" * 50)
    
    session = requests.Session()
    session.headers.update({
        'Origin': VERCEL_URL,
        'Referer': VERCEL_URL,
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    })
    
    steps = []
    
    # Paso 1: Auto-login
    print("   🔐 Paso 1: Auto-login...")
    try:
        login_response = session.post(f"{RENDER_API}/api/login", json={
            "username": "admin", 
            "password": "admin123"
        }, timeout=10)
        
        login_success = login_response.status_code == 200
        steps.append(("Auto-login", login_success, login_response.status_code))
        print(f"      {'✅' if login_success else '❌'} Status: {login_response.status_code}")
        
        if not login_success:
            print(f"      Error: {login_response.text[:200]}")
            
    except Exception as e:
        steps.append(("Auto-login", False, f"Exception: {e}"))
        print(f"      ❌ Error: {e}")
        return steps
    
    # Paso 2: Registrar datos demográficos
    print("   📝 Paso 2: Registrar datos demográficos...")
    demo_data = {
        "name": "Usuario Vercel Test",
        "email": "test@vercel.com",
        "age": 30,
        "gender": "masculino"
    }
    
    try:
        # Intentar endpoint principal
        demo_response = session.post(f"{RENDER_API}/api/register", json=demo_data, timeout=10)
        demo_success = demo_response.status_code == 200
        
        if not demo_success:
            # Intentar endpoint alternativo
            demo_response = session.post(f"{RENDER_API}/api/demographics", json=demo_data, timeout=10)
            demo_success = demo_response.status_code == 200
            print(f"      Usado endpoint alternativo /api/demographics")
        
        steps.append(("Datos demográficos", demo_success, demo_response.status_code))
        print(f"      {'✅' if demo_success else '❌'} Status: {demo_response.status_code}")
        
        if not demo_success:
            print(f"      Error: {demo_response.text[:200]}")
            
    except Exception as e:
        steps.append(("Datos demográficos", False, f"Exception: {e}"))
        print(f"      ❌ Error: {e}")
        return steps
    
    # Paso 3: Obtener preguntas
    print("   ❓ Paso 3: Obtener preguntas...")
    try:
        questions_response = session.get(f"{RENDER_API}/api/questions", timeout=10)
        questions_success = questions_response.status_code == 200
        
        steps.append(("Obtener preguntas", questions_success, questions_response.status_code))
        print(f"      {'✅' if questions_success else '❌'} Status: {questions_response.status_code}")
        
        if questions_success:
            questions_data = questions_response.json()
            questions_count = len(questions_data.get('questions', []))
            print(f"      📊 Preguntas obtenidas: {questions_count}")
        else:
            print(f"      Error: {questions_response.text[:200]}")
            
    except Exception as e:
        steps.append(("Obtener preguntas", False, f"Exception: {e}"))
        print(f"      ❌ Error: {e}")
    
    return steps

def main():
    """Ejecutar diagnóstico completo"""
    print("🚨 DIAGNÓSTICO COMPLETO: Problema iniciar evaluación en Vercel")
    print("=" * 70)
    print(f"🌐 Frontend: {VERCEL_URL}")
    print(f"🔧 Backend: {RENDER_API}")
    print(f"⏰ Timestamp: {datetime.now().strftime('%H:%M:%S')}")
    print()
    
    # Tests
    frontend_ok = test_frontend_content()
    api_results = test_api_endpoints_individually()
    cors_ok = test_cors_specifically()
    button_steps = simulate_button_click()
    
    print("\n" + "=" * 70)
    print("📊 RESUMEN DEL DIAGNÓSTICO:")
    print("=" * 70)
    
    print(f"Frontend Content: {'✅ OK' if frontend_ok else '❌ PROBLEMA'}")
    print(f"CORS Config: {'✅ OK' if cors_ok else '❌ PROBLEMA'}")
    
    print("\nAPI Endpoints:")
    for endpoint, result in api_results.items():
        status = "✅ OK" if result['success'] else "❌ FALLA"
        print(f"   {endpoint}: {status} ({result['status']})")
    
    print("\nSimulación de botón:")
    for step_name, success, status in button_steps:
        status_icon = "✅" if success else "❌"
        print(f"   {step_name}: {status_icon} ({status})")
    
    # Identificar problemas
    print("\n🎯 PROBLEMAS IDENTIFICADOS:")
    if not frontend_ok:
        print("   ❌ Problema en contenido del frontend")
    if not cors_ok:
        print("   ❌ Problema en configuración CORS")
    
    failing_apis = [ep for ep, result in api_results.items() if not result['success']]
    if failing_apis:
        print(f"   ❌ APIs fallando: {', '.join(failing_apis)}")
    
    failing_steps = [step for step, success, _ in button_steps if not success]
    if failing_steps:
        print(f"   ❌ Pasos fallando: {', '.join(failing_steps)}")
    
    if frontend_ok and cors_ok and not failing_apis and not failing_steps:
        print("   ✅ No se encontraron problemas técnicos")
        print("   ⚠️  El problema puede ser en el JavaScript del frontend")
        print("   💡 Revisar consola del navegador para errores JavaScript")
    
    print("=" * 70)

if __name__ == "__main__":
    main()
