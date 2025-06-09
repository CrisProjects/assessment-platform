#!/usr/bin/env python3
"""
Test completo del flujo de login y obtención de preguntas
"""
import requests
import json

def test_full_evaluation_flow():
    """Prueba el flujo completo de login y obtención de preguntas"""
    print("🧪 PRUEBA COMPLETA DEL FLUJO DE EVALUACIÓN")
    print("=" * 60)
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    # Crear sesión para mantener cookies
    session = requests.Session()
    
    print("1. 🔐 Intentando login con admin/admin123...")
    login_data = {"username": "admin", "password": "admin123"}
    try:
        response = session.post(f"{base_url}/api/login", json=login_data, timeout=15)
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type', 'N/A')}")
        
        if response.status_code == 200:
            login_result = response.json()
            if login_result.get('success'):
                print("   ✅ Login exitoso")
                print(f"   Usuario: {login_result.get('user', {}).get('username')}")
                print(f"   Admin: {login_result.get('user', {}).get('is_admin')}")
            else:
                print("   ❌ Login falló")
                print(f"   Error: {login_result.get('error')}")
                return
        else:
            print("   ❌ Error de conexión en login")
            print(f"   Respuesta: {response.text[:200]}")
            return
            
    except Exception as e:
        print(f"   ❌ Excepción en login: {e}")
        return
    
    print("\n2. 📋 Intentando obtener preguntas...")
    try:
        response = session.get(f"{base_url}/api/questions", timeout=15)
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type', 'N/A')}")
        
        if response.status_code == 200:
            try:
                questions_data = response.json()
                questions = questions_data.get('questions', [])
                print(f"   ✅ Preguntas obtenidas: {len(questions)} preguntas")
                
                if questions:
                    print(f"   Primera pregunta: {questions[0].get('content', 'N/A')[:50]}...")
                    print(f"   Opciones: {len(questions[0].get('options', []))}")
                else:
                    print("   ⚠️ No se encontraron preguntas")
                    
            except json.JSONDecodeError:
                print("   ❌ Respuesta no es JSON válido")
                print(f"   Respuesta: {response.text[:200]}")
        else:
            print(f"   ❌ Error obteniendo preguntas (Status: {response.status_code})")
            print(f"   Respuesta: {response.text[:200]}")
            
    except Exception as e:
        print(f"   ❌ Excepción obteniendo preguntas: {e}")
        return
    
    print("\n3. 🏥 Verificando salud del API...")
    try:
        response = session.get(f"{base_url}/api/health", timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            health_data = response.json()
            print(f"   ✅ API saludable: {health_data.get('status')}")
            print(f"   Base de datos: {health_data.get('database')}")
        else:
            print("   ❌ API no saludable")
    except Exception as e:
        print(f"   ❌ Error verificando salud: {e}")
    
    print("\n" + "=" * 60)
    print("🎯 RESUMEN: El problema parece estar en el endpoint /api/questions")
    print("   - Se requiere autenticación de sesión válida")
    print("   - Puede haber un error interno del servidor")
    print("   - Verificar logs de Render para más detalles")

if __name__ == "__main__":
    test_full_evaluation_flow()
