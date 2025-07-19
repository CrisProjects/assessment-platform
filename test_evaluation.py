#!/usr/bin/env python3
"""
Script para simular una evaluación completa
"""
import requests
import json

def test_complete_evaluation():
    session = requests.Session()
    
    # Login
    print("=== LOGIN ===")
    login = session.post('http://localhost:5003/api/login', json={
        'username': 'coachee@assessment.com',
        'password': 'coachee123'
    })
    print(f"Status: {login.status_code}")
    
    if login.status_code != 200:
        print("Error en login")
        return
    
    # Obtener preguntas
    print("\n=== OBTENER PREGUNTAS ===")
    questions_response = session.get('http://localhost:5003/api/questions')
    print(f"Status: {questions_response.status_code}")
    
    if questions_response.status_code != 200:
        print("Error obteniendo preguntas")
        return
    
    questions_data = questions_response.json()
    questions = questions_data.get('questions', [])
    print(f"Preguntas obtenidas: {len(questions)}")
    
    # Simular respuestas (todas con valor 4 = "De acuerdo")
    responses = []
    for question in questions:
        responses.append({
            'question_id': question['id'],
            'selected_option': 4  # "De acuerdo"
        })
    
    print(f"Respuestas preparadas: {len(responses)}")
    
    # Enviar evaluación
    print("\n=== ENVIAR EVALUACIÓN ===")
    assessment_data = {
        'age': 25,
        'gender': 'no_especificado',
        'responses': responses
    }
    
    save_response = session.post(
        'http://localhost:5003/api/save_assessment',
        json=assessment_data
    )
    
    print(f"Status: {save_response.status_code}")
    result = save_response.json()
    print(f"Response: {result}")
    
    if save_response.status_code == 200:
        print("\n✅ EVALUACIÓN COMPLETADA EXITOSAMENTE")
        print(f"Score: {result.get('score', 'N/A')}%")
        print(f"Resultado: {result.get('result_text', 'N/A')}")
    else:
        print("\n❌ ERROR EN EVALUACIÓN")
        print(f"Error: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    test_complete_evaluation()
