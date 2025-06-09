#!/usr/bin/env python3
"""
Script para probar el flujo completo de evaluación después de la corrección
"""
import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_complete_flow():
    """Prueba completa del flujo de evaluación"""
    session = requests.Session()
    
    print("🔄 Iniciando prueba completa del flujo de evaluación...")
    
    # 1. Verificar que la aplicación esté funcionando
    print("\n1. Verificando estado de la aplicación...")
    health_response = session.get(f"{BASE_URL}/api/health")
    if health_response.status_code == 200:
        print("✅ Aplicación funcionando correctamente")
        print(f"   Estado: {health_response.json()}")
    else:
        print(f"❌ Error en aplicación: {health_response.status_code}")
        return False
    
    # 2. Hacer login
    print("\n2. Haciendo login como admin...")
    login_data = {"username": "admin", "password": "admin123"}
    login_response = session.post(f"{BASE_URL}/api/login", json=login_data)
    
    if login_response.status_code == 200:
        print("✅ Login exitoso")
        print(f"   Usuario: {login_response.json()['user']['username']}")
    else:
        print(f"❌ Error en login: {login_response.status_code}")
        return False
    
    # 3. Obtener preguntas de evaluación
    print("\n3. Obteniendo preguntas de evaluación...")
    questions_response = session.get(f"{BASE_URL}/api/questions")
    
    if questions_response.status_code == 200:
        questions_data = questions_response.json()
        questions = questions_data['questions']
        print(f"✅ Preguntas obtenidas exitosamente")
        print(f"   Cantidad de preguntas: {len(questions)}")
        print(f"   Primera pregunta: {questions[0]['content'][:50]}...")
    else:
        print(f"❌ Error obteniendo preguntas: {questions_response.status_code}")
        print(f"   Respuesta: {questions_response.text}")
        return False
    
    # 4. Simular respuestas a la evaluación
    print("\n4. Simulando respuestas a la evaluación...")
    responses = []
    for i, question in enumerate(questions):
        # Simular respuesta (siempre la segunda opción para consistencia)
        responses.append({
            "question_id": question['id'],
            "selected_option": 1,  # índice de la segunda opción (más asertiva)
            "option_text": question['options'][1]
        })
    
    assessment_data = {
        "assessment_id": 1,  # ID de la evaluación de asertividad
        "responses": responses
    }
    
    save_response = session.post(f"{BASE_URL}/api/save_assessment", json=assessment_data)
    
    if save_response.status_code == 200:
        result = save_response.json()
        print("✅ Evaluación guardada exitosamente")
        print(f"   Puntuación: {result.get('score', 'N/A')}")
        print(f"   Nivel de asertividad: {result.get('assertiveness_level', 'N/A')}")
    else:
        print(f"❌ Error guardando evaluación: {save_response.status_code}")
        print(f"   Respuesta: {save_response.text}")
        return False
    
    print("\n🎉 ¡FLUJO COMPLETO EXITOSO!")
    print("   El botón 'Iniciar Evaluación' ahora debería funcionar correctamente.")
    return True

if __name__ == "__main__":
    success = test_complete_flow()
    if success:
        print("\n✅ EVALUACIÓN COMPLETADA - La plataforma está funcionando correctamente")
    else:
        print("\n❌ EVALUACIÓN FALLIDA - Hay problemas que necesitan atención")
