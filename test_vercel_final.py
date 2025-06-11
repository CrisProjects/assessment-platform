#!/usr/bin/env python3
"""
🎉 TEST FINAL: Verificación Vercel ↔ Render COMPLETA
===================================================

Ahora que encontramos la URL correcta de Vercel, vamos a verificar
que toda la plataforma funcione de extremo a extremo.
"""

import requests
import json

# URLs correctas identificadas
VERCEL_FRONTEND = "https://assessment-platform-final.vercel.app"
RENDER_BACKEND = "https://assessment-platform-1nuo.onrender.com"

def test_vercel_frontend():
    """Probar frontend de Vercel"""
    print("🌐 Testing: Frontend de Vercel")
    print("-" * 40)
    
    try:
        response = requests.get(VERCEL_FRONTEND, timeout=10)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            content = response.text
            has_title = "Plataforma de Evaluación" in content
            has_button = "Comenzar Evaluación" in content
            has_form = "name" in content and "email" in content
            
            print(f"✅ Frontend carga: {has_title}")
            print(f"✅ Botón presente: {has_button}")
            print(f"✅ Formulario presente: {has_form}")
            
            return has_title and has_button and has_form
        else:
            print(f"❌ Error HTTP: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_cors_connectivity():
    """Probar conectividad CORS"""
    print("\n🔗 Testing: CORS Vercel → Render")
    print("-" * 40)
    
    headers = {
        'Origin': VERCEL_FRONTEND,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type'
    }
    
    try:
        response = requests.options(f"{RENDER_BACKEND}/api/login", headers=headers, timeout=10)
        allow_origin = response.headers.get('Access-Control-Allow-Origin')
        
        print(f"Status: {response.status_code}")
        print(f"Allow-Origin: {allow_origin}")
        
        cors_ok = allow_origin and (VERCEL_FRONTEND in allow_origin or allow_origin == '*')
        print(f"✅ CORS configurado: {cors_ok}")
        
        return cors_ok
    except Exception as e:
        print(f"❌ Error CORS: {e}")
        return False

def test_full_api_flow():
    """Probar flujo completo de API"""
    print("\n🚀 Testing: Flujo completo de API")
    print("-" * 40)
    
    session = requests.Session()
    session.headers.update({'Origin': VERCEL_FRONTEND})
    
    try:
        # 1. Login
        login_response = session.post(f"{RENDER_BACKEND}/api/login", json={
            "username": "admin",
            "password": "admin123"
        }, timeout=10)
        
        print(f"Login Status: {login_response.status_code}")
        login_ok = login_response.status_code == 200
        
        if not login_ok:
            print("❌ Login falló")
            return False
        
        # 2. Register demographics
        demo_response = session.post(f"{RENDER_BACKEND}/api/register", json={
            "name": "Test Vercel User",
            "email": "test@vercel.com",
            "age": 25,
            "gender": "masculino"
        }, timeout=10)
        
        print(f"Demographics Status: {demo_response.status_code}")
        demo_ok = demo_response.status_code == 200
        
        # 3. Get questions
        questions_response = session.get(f"{RENDER_BACKEND}/api/questions", timeout=10)
        print(f"Questions Status: {questions_response.status_code}")
        questions_ok = questions_response.status_code == 200
        
        if questions_ok:
            questions_data = questions_response.json()
            questions = questions_data.get('questions', [])
            print(f"Questions count: {len(questions)}")
        
        # 4. Submit assessment
        if questions_ok and len(questions) > 0:
            responses = []
            for q in questions[:3]:  # Solo las primeras 3 para prueba rápida
                responses.append({
                    "question_id": q['id'],
                    "selected_option": 1,
                    "option_text": q['options'][1] if len(q['options']) > 1 else q['options'][0]
                })
            
            submit_response = session.post(f"{RENDER_BACKEND}/api/submit", json={
                "assessment_id": 1,
                "responses": responses
            }, timeout=10)
            
            print(f"Submit Status: {submit_response.status_code}")
            submit_ok = submit_response.status_code == 200
            
            if submit_ok:
                result = submit_response.json()
                print(f"✅ Score: {result.get('score', 'N/A')}%")
                print(f"✅ Level: {result.get('score_level', 'N/A')}")
        else:
            submit_ok = False
        
        return login_ok and demo_ok and questions_ok and submit_ok
        
    except Exception as e:
        print(f"❌ Error en flujo: {e}")
        return False

def main():
    """Ejecutar verificación completa"""
    print("🎯 VERIFICACIÓN FINAL: Vercel ↔ Render")
    print("=" * 50)
    print(f"Frontend: {VERCEL_FRONTEND}")
    print(f"Backend: {RENDER_BACKEND}")
    print()
    
    # Tests
    frontend_ok = test_vercel_frontend()
    cors_ok = test_cors_connectivity()
    api_ok = test_full_api_flow()
    
    print("\n" + "=" * 50)
    print("📊 RESUMEN FINAL:")
    print("=" * 50)
    print(f"Frontend Vercel: {'✅ FUNCIONA' if frontend_ok else '❌ FALLA'}")
    print(f"CORS Config: {'✅ FUNCIONA' if cors_ok else '❌ FALLA'}")
    print(f"API Flow: {'✅ FUNCIONA' if api_ok else '❌ FALLA'}")
    
    all_ok = frontend_ok and cors_ok and api_ok
    
    print(f"\n🎯 RESULTADO FINAL: {'🎉 VERCEL FUNCIONANDO AL 100%' if all_ok else '❌ HAY PROBLEMAS'}")
    
    if all_ok:
        print("\n✅ CONFIRMADO: Vercel está completamente operativo")
        print("🌐 Los usuarios pueden usar:")
        print(f"   • {VERCEL_FRONTEND}")
        print(f"   • {RENDER_BACKEND} (también disponible)")
        print("\n🎉 ¡AMBOS DEPLOYMENTS FUNCIONAN!")
    else:
        print("\n❌ Revisar configuración...")
    
    print("=" * 50)

if __name__ == "__main__":
    main()
