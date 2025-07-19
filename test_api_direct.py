#!/usr/bin/env python3
"""
Script para probar la API directamente, simulando las llamadas del navegador
"""

import requests
import json

def test_api_save_assessment():
    """Probar el endpoint de guardado de evaluación"""
    print("=== TESTING SAVE ASSESSMENT API ===")
    
    # Preparar datos de evaluación
    assessment_data = {
        'age': 25,
        'gender': 'no_especificado',
        'responses': [
            {'question_id': 1, 'selected_option': 4},
            {'question_id': 2, 'selected_option': 5},
            {'question_id': 3, 'selected_option': 3},
            {'question_id': 4, 'selected_option': 4},
            {'question_id': 5, 'selected_option': 4}
        ]
    }
    
    # Usar cookies para simular una sesión de navegador
    cookies = {
        'session': 'test-session-cookie'
    }
    
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    }
    
    try:
        response = requests.post(
            'http://127.0.0.1:5002/api/save_assessment',
            json=assessment_data,
            headers=headers,
            cookies=cookies
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ SUCCESS! Response data:")
            print(json.dumps(data, indent=2))
            
            # Verificar campos esperados
            required_fields = ['success', 'score', 'result_text', 'assessment_id']
            missing_fields = [field for field in required_fields if field not in data]
            
            if not missing_fields:
                print("✅ All required fields present")
            else:
                print(f"❌ Missing fields: {missing_fields}")
                
        else:
            print(f"❌ ERROR: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

def test_coach_api():
    """Probar el endpoint del coach"""
    print("\n=== TESTING COACH API ===")
    
    try:
        # Test endpoint de coachees
        response = requests.get(
            'http://127.0.0.1:5002/api/coach/my-coachees',
            headers={'User-Agent': 'Mozilla/5.0'},
        )
        
        print(f"Coachees API Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Coachees found: {len(data)}")
            
            if data:
                coachee_id = data[0]['id']
                print(f"Testing evaluations for coachee {coachee_id}...")
                
                # Test endpoint de evaluaciones del coachee
                response = requests.get(
                    f'http://127.0.0.1:5002/api/coach/coachee-evaluations/{coachee_id}',
                    headers={'User-Agent': 'Mozilla/5.0'},
                )
                
                print(f"Evaluations API Status: {response.status_code}")
                if response.status_code == 200:
                    data = response.json()
                    print("✅ SUCCESS! Evaluations data:")
                    print(json.dumps(data, indent=2)[:500] + "..." if len(str(data)) > 500 else json.dumps(data, indent=2))
                else:
                    print(f"❌ ERROR: {response.text}")
        else:
            print(f"❌ ERROR: {response.text}")
            
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    test_api_save_assessment()
    test_coach_api()
    
    print("\n" + "="*50)
    print("📝 NOTES:")
    print("- APIs may require proper authentication")
    print("- Test in browser console for actual session cookies")
    print("- Check network tab in DevTools for working requests")
