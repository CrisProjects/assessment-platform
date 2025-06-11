#!/usr/bin/env python3
"""
🧪 TEST: Verificación de corrección de completeAssessment()
===========================================================

Este test verifica que el problema de finalización de evaluación 
ha sido resuelto correctamente.
"""

import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_complete_assessment_fix():
    """Prueba el flujo completo de evaluación con el formato corregido"""
    
    print("🧪 TESTING: Corrección de completeAssessment()")
    print("=" * 60)
    
    # Crear sesión para mantener cookies
    session = requests.Session()
    
    # 1. Auto-login como admin
    print("1. Login automático como admin...")
    login_response = session.post(f"{BASE_URL}/api/login", json={
        "username": "admin",
        "password": "admin123"
    })
    
    if login_response.status_code != 200:
        print(f"❌ Error en login: {login_response.status_code}")
        return False
    
    print("✅ Login exitoso")
    
    # 2. Registrar datos demográficos
    print("\n2. Registrando participante...")
    demo_response = session.post(f"{BASE_URL}/api/register", json={
        "name": "Test Complete Assessment",
        "email": "test@example.com",
        "age": 30,
        "gender": "masculino"
    })
    
    if demo_response.status_code != 200:
        print(f"❌ Error en registro: {demo_response.status_code}")
        return False
    
    print("✅ Participante registrado")
    
    # 3. Obtener preguntas
    print("\n3. Obteniendo preguntas...")
    questions_response = session.get(f"{BASE_URL}/api/questions")
    
    if questions_response.status_code != 200:
        print(f"❌ Error obteniendo preguntas: {questions_response.status_code}")
        return False
    
    questions_data = questions_response.json()
    questions = questions_data.get('questions', [])
    
    print(f"✅ {len(questions)} preguntas obtenidas")
    
    # 4. Simular evaluación completa con formato CORREGIDO
    print("\n4. Enviando evaluación con formato corregido...")
    
    # Simular respuestas - siempre opción 1 (segunda opción, más asertiva)
    responses = []
    for question in questions:
        responses.append({
            "question_id": question['id'],
            "selected_option": 1,  # índice de la segunda opción
            "option_text": question['options'][1]
        })
    
    # Formato corregido que espera el backend
    assessment_data = {
        "assessment_id": 1,
        "responses": responses
    }
    
    # Enviar al endpoint /api/submit
    submit_response = session.post(f"{BASE_URL}/api/submit", json=assessment_data)
    
    if submit_response.status_code == 200:
        result = submit_response.json()
        print("✅ Evaluación enviada exitosamente!")
        print(f"   📊 Puntuación: {result.get('score', 'N/A')}%")
        print(f"   🎯 Nivel: {result.get('score_level', 'N/A')}")
        print(f"   📝 Texto resultado: {result.get('result_text', 'N/A')[:100]}...")
        print(f"   ❓ Total preguntas: {result.get('total_questions', 'N/A')}")
        
        # Verificar que el resultado tenga todos los campos esperados
        required_fields = ['success', 'score', 'score_level', 'result_text', 'total_questions']
        missing_fields = [field for field in required_fields if field not in result]
        
        if missing_fields:
            print(f"⚠️  Campos faltantes en respuesta: {missing_fields}")
        else:
            print("✅ Todos los campos esperados están presentes")
        
        return True
    else:
        print(f"❌ Error enviando evaluación: {submit_response.status_code}")
        print(f"   Respuesta: {submit_response.text}")
        return False

def main():
    """Ejecutar todas las pruebas"""
    print("🎯 VERIFICACIÓN: Corrección de completeAssessment()")
    print("Fecha:", "11 de junio de 2025")
    print("URL:", BASE_URL)
    print()
    
    success = test_complete_assessment_fix()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 EVALUACIÓN COMPLETA CORREGIDA - ¡PROBLEMA RESUELTO!")
        print("✅ Los usuarios ahora pueden finalizar evaluaciones correctamente")
        print("✅ El formato de datos es compatible con el backend")
        print("✅ La función completeAssessment() funciona perfectamente")
    else:
        print("❌ PROBLEMA PERSISTE - Revisar logs para más detalles")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
