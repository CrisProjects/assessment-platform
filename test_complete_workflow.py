#!/usr/bin/env python3
"""
Script para probar el flujo completo de evaluación:
1. Login como coachee
2. Completar evaluación
3. Verificar que se muestra el resultado con porcentaje
4. Login como coach
5. Ver detalles de evaluación del coachee
"""

import requests
import json

BASE_URL = "http://127.0.0.1:5002"

def test_coachee_evaluation():
    print("=== TESTING COACHEE EVALUATION WORKFLOW ===")
    
    # Crear sesión
    session = requests.Session()
    
    # 1. Login como coachee
    print("\n1. Login como coachee...")
    login_data = {
        'username': 'coachee',
        'password': 'coachee123'
    }
    
    response = session.post(f"{BASE_URL}/login", data=login_data)
    print(f"Login status: {response.status_code}")
    
    if response.status_code != 200:
        print("Error en login, probando registro...")
        register_data = {
            'username': 'coachee',
            'email': 'coachee@assessment.com',
            'full_name': 'Coachee de Prueba',
            'password': 'coachee123',
            'role': 'coachee'
        }
        response = session.post(f"{BASE_URL}/register", data=register_data)
        print(f"Register status: {response.status_code}")
        
        # Intentar login nuevamente
        response = session.post(f"{BASE_URL}/login", data=login_data)
        print(f"Login after register: {response.status_code}")
    
    # 2. Obtener preguntas
    print("\n2. Obteniendo preguntas...")
    response = session.get(f"{BASE_URL}/api/questions")
    print(f"Questions status: {response.status_code}")
    
    if response.status_code == 200:
        questions_data = response.json()
        print(f"Questions received: {len(questions_data.get('questions', []))}")
        
        # 3. Enviar respuestas de evaluación
        print("\n3. Enviando evaluación...")
        responses = []
        for i, question in enumerate(questions_data.get('questions', [])[:5]):  # Solo primeras 5
            responses.append({
                'question_id': question['id'],
                'selected_option': 4  # Respuesta "De acuerdo"
            })
        
        assessment_data = {
            'age': 25,
            'gender': 'no_especificado',
            'responses': responses
        }
        
        response = session.post(f"{BASE_URL}/api/save_assessment", 
                               json=assessment_data,
                               headers={'Content-Type': 'application/json'})
        
        print(f"Assessment save status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"✅ EVALUATION COMPLETED!")
            print(f"   Score: {result.get('score')}%")
            print(f"   Result Text: {result.get('result_text')}")
            print(f"   Assessment ID: {result.get('assessment_id')}")
            
            # Verificar que tiene los campos necesarios para mostrar en frontend
            if result.get('score') and result.get('result_text'):
                print("✅ Los campos necesarios para mostrar el resultado están presentes")
            else:
                print("❌ Faltan campos en la respuesta del API")
            
            return result.get('assessment_id')
        else:
            print(f"❌ Error saving assessment: {response.text}")
            return None
    else:
        print(f"❌ Error getting questions: {response.text}")
        return None

def test_coach_view():
    print("\n\n=== TESTING COACH VIEW WORKFLOW ===")
    
    # Crear nueva sesión para coach
    session = requests.Session()
    
    # 1. Login como coach
    print("\n1. Login como coach...")
    login_data = {
        'username': 'coach',
        'password': 'coach123'
    }
    
    response = session.post(f"{BASE_URL}/coach-login", data=login_data)
    print(f"Coach login status: {response.status_code}")
    
    # 2. Obtener coachees
    print("\n2. Obteniendo coachees...")
    response = session.get(f"{BASE_URL}/api/coach/my-coachees")
    print(f"Coachees status: {response.status_code}")
    
    if response.status_code == 200:
        coachees = response.json()
        print(f"Coachees found: {len(coachees)}")
        
        if coachees:
            coachee = coachees[0]
            print(f"First coachee: {coachee.get('full_name')} (ID: {coachee.get('id')})")
            
            # 3. Ver evaluaciones del coachee
            print(f"\n3. Viendo evaluaciones del coachee {coachee.get('id')}...")
            response = session.get(f"{BASE_URL}/api/coach/coachee-evaluations/{coachee.get('id')}")
            print(f"Coachee evaluations status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ COACH CAN VIEW COACHEE EVALUATIONS!")
                print(f"   Coachee: {data.get('coachee', {}).get('name')}")
                evaluations = data.get('evaluations', [])
                print(f"   Evaluations: {len(evaluations)}")
                
                for i, eval in enumerate(evaluations):
                    print(f"   Eval {i+1}: {eval.get('score')}% - {eval.get('result_text')[:50]}...")
                    print(f"            Responses: {len(eval.get('responses', []))}")
                
                return True
            else:
                print(f"❌ Error getting coachee evaluations: {response.text}")
                return False
        else:
            print("❌ No coachees found")
            return False
    else:
        print(f"❌ Error getting coachees: {response.text}")
        return False

if __name__ == "__main__":
    # Test completo
    evaluation_id = test_coachee_evaluation()
    coach_success = test_coach_view()
    
    print("\n" + "="*50)
    print("SUMMARY:")
    print(f"✅ Coachee Evaluation: {'SUCCESS' if evaluation_id else 'FAILED'}")
    print(f"✅ Coach View: {'SUCCESS' if coach_success else 'FAILED'}")
    
    if evaluation_id and coach_success:
        print("\n🎉 ALL TESTS PASSED! The complete workflow is working!")
    else:
        print("\n❌ Some tests failed. Check the issues above.")
