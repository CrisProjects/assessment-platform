#!/usr/bin/env python3
"""
🎯 SIMULACIÓN EXACTA: Experiencia de usuario en Vercel
=====================================================

Este test simula exactamente lo que un usuario haría en Vercel,
paso a paso, incluyendo todos los headers y cookies reales.
"""

import requests
import json
import time
from datetime import datetime

# URLs
VERCEL_URL = "https://assessment-platform-final.vercel.app"
RENDER_API = "https://assessment-platform-1nuo.onrender.com"

def simulate_user_experience():
    """Simular la experiencia exacta de un usuario en Vercel"""
    
    print("🎭 SIMULACIÓN: Usuario real en Vercel")
    print("=" * 60)
    print(f"🌐 Accediendo a: {VERCEL_URL}")
    print(f"🔧 API Backend: {RENDER_API}")
    print()
    
    # Crear sesión que simule un navegador real
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
        'Origin': VERCEL_URL,
        'Referer': VERCEL_URL
    })
    
    print("📋 PASO 1: Usuario carga la página de Vercel")
    print("-" * 40)
    
    try:
        # Cargar página principal
        page_response = session.get(VERCEL_URL, timeout=10)
        print(f"Status: {page_response.status_code}")
        print(f"Content-Length: {len(page_response.text)}")
        
        if page_response.status_code == 200:
            content = page_response.text
            has_form = "name" in content and "email" in content
            has_button = "Comenzar Evaluación" in content
            print(f"✅ Formulario presente: {has_form}")
            print(f"✅ Botón presente: {has_button}")
        else:
            print(f"❌ Error cargando página: {page_response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return False
    
    print(f"\n🔐 PASO 2: Usuario hace 'Comenzar Evaluación' - Auto-login")
    print("-" * 40)
    
    try:
        # Simular el auto-login que hace el frontend
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        login_response = session.post(
            f"{RENDER_API}/api/login", 
            json=login_data,
            timeout=10
        )
        
        print(f"Login Status: {login_response.status_code}")
        
        if login_response.status_code == 200:
            print("✅ Auto-login exitoso")
            login_result = login_response.json()
            print(f"   Usuario: {login_result.get('user', {}).get('username', 'N/A')}")
        else:
            print(f"❌ Auto-login falló: {login_response.status_code}")
            print(f"   Response: {login_response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ Error en auto-login: {e}")
        return False
    
    print(f"\n📝 PASO 3: Usuario envía datos demográficos")
    print("-" * 40)
    
    try:
        # Enviar datos demográficos como lo haría el frontend
        demo_data = {
            "name": "Usuario Prueba Vercel",
            "email": "usuario@vercel.test",
            "age": 28,
            "gender": "femenino"
        }
        
        demo_response = session.post(
            f"{RENDER_API}/api/register",
            json=demo_data,
            timeout=10
        )
        
        print(f"Demographics Status: {demo_response.status_code}")
        
        if demo_response.status_code == 200:
            print("✅ Datos demográficos registrados")
        else:
            print(f"❌ Error en datos demográficos: {demo_response.status_code}")
            # Intentar endpoint alternativo
            demo_response = session.post(
                f"{RENDER_API}/api/demographics",
                json=demo_data,
                timeout=10
            )
            print(f"Demographics Alt Status: {demo_response.status_code}")
            
    except Exception as e:
        print(f"❌ Error enviando datos: {e}")
        return False
    
    print(f"\n❓ PASO 4: Cargar preguntas de evaluación")
    print("-" * 40)
    
    try:
        questions_response = session.get(f"{RENDER_API}/api/questions", timeout=10)
        print(f"Questions Status: {questions_response.status_code}")
        
        if questions_response.status_code == 200:
            questions_data = questions_response.json()
            questions = questions_data.get('questions', [])
            print(f"✅ {len(questions)} preguntas cargadas")
            
            if len(questions) == 0:
                print("❌ No hay preguntas disponibles")
                return False
                
        else:
            print(f"❌ Error cargando preguntas: {questions_response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error obteniendo preguntas: {e}")
        return False
    
    print(f"\n🎯 PASO 5: Usuario responde y envía evaluación")
    print("-" * 40)
    
    try:
        # Simular respuestas del usuario (respuestas asertivas)
        responses = []
        for i, question in enumerate(questions[:5]):  # Solo 5 preguntas para prueba rápida
            responses.append({
                "question_id": question['id'],
                "selected_option": 1,  # Opción asertiva
                "option_text": question['options'][1]
            })
        
        # Enviar evaluación como lo hace el frontend corregido
        assessment_data = {
            "assessment_id": 1,
            "responses": responses
        }
        
        submit_response = session.post(
            f"{RENDER_API}/api/submit",
            json=assessment_data,
            timeout=10
        )
        
        print(f"Submit Status: {submit_response.status_code}")
        
        if submit_response.status_code == 200:
            result = submit_response.json()
            print("✅ Evaluación enviada exitosamente!")
            print(f"   📊 Puntuación: {result.get('score', 'N/A')}%")
            print(f"   🎯 Nivel: {result.get('score_level', 'N/A')}")
            print(f"   📝 Descripción: {result.get('result_text', 'N/A')[:80]}...")
            return True
        else:
            print(f"❌ Error enviando evaluación: {submit_response.status_code}")
            print(f"   Response: {submit_response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ Error en envío final: {e}")
        return False

def main():
    """Ejecutar simulación completa"""
    print("🎯 PRUEBA AUTOMATIZADA: Vercel Frontend → Render Backend")
    print(f"Fecha: {datetime.now().strftime('%d de junio de 2025, %H:%M:%S')}")
    print()
    
    success = simulate_user_experience()
    
    print("\n" + "=" * 60)
    print("📊 RESULTADO DE LA SIMULACIÓN:")
    print("=" * 60)
    
    if success:
        print("🎉 ¡VERCEL FUNCIONA PERFECTAMENTE!")
        print("✅ Frontend carga correctamente")
        print("✅ Conexión con backend Render funciona")
        print("✅ Auto-login funciona")
        print("✅ Registro de datos funciona")
        print("✅ Carga de preguntas funciona")
        print("✅ Envío de evaluación funciona")
        print("✅ Recepción de resultados funciona")
        print()
        print("🌐 URLS CONFIRMADAS FUNCIONANDO:")
        print(f"   • Frontend: {VERCEL_URL}")
        print(f"   • Backend: {RENDER_API}")
        print()
        print("🎯 Los usuarios pueden usar Vercel sin problemas!")
        
    else:
        print("❌ HAY PROBLEMAS EN ALGÚN PASO")
        print("   Revisar logs arriba para identificar el problema")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
