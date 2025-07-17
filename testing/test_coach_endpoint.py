#!/usr/bin/env python3
"""
Script para probar el endpoint del coach de evaluación de coachees
"""
import requests
import json

def test_coach_login_and_evaluation():
    base_url = "http://127.0.0.1:10000"
    session = requests.Session()
    
    print("=== Probando login del coach ===")
    
    # Login como coach
    login_data = {
        'username': 'coach_test',
        'password': 'test123'
    }
    
    login_response = session.post(f"{base_url}/api/coach/login", json=login_data)
    print(f"Login status: {login_response.status_code}")
    
    if login_response.status_code != 200:
        print("Error en login del coach")
        return
    
    print("✓ Login del coach exitoso")
    
    # Obtener lista de coachees
    print("\n=== Obteniendo coachees asignados ===")
    coachees_response = session.get(f"{base_url}/api/coach/my-coachees")
    print(f"Coachees status: {coachees_response.status_code}")
    
    if coachees_response.status_code == 200:
        coachees_data = coachees_response.json()
        print(f"✓ Coachees encontrados: {len(coachees_data)}")
        
        if coachees_data:
            # Tomar el primer coachee con evaluación
            for coachee in coachees_data:
                print(f"Coachee: {coachee['full_name']} (ID: {coachee['id']})")
                print(f"  Total evaluaciones: {coachee.get('total_assessments', 0)}")
                print(f"  Última evaluación: {coachee.get('last_assessment', 'None')}")
                
                if coachee.get('last_assessment'):
                    coachee_id = coachee['id']
                    print(f"✓ Coachee con evaluación: {coachee['full_name']} (ID: {coachee_id})")
                    
                    # Probar endpoint de evaluación del coachee
                    print(f"\n=== Probando detalles de evaluación del coachee {coachee_id} ===")
                    eval_response = session.get(f"{base_url}/api/coach/coachee-evaluation-details/{coachee_id}")
                    print(f"Evaluation details status: {eval_response.status_code}")
                    
                    if eval_response.status_code == 200:
                        eval_data = eval_response.json()
                        print("✓ Detalles de evaluación obtenidos exitosamente")
                        print(f"Score total: {eval_data.get('evaluation', {}).get('total_score', 'N/A')}")
                        print(f"Nivel de asertividad: {eval_data.get('evaluation', {}).get('assertiveness_level', 'N/A')}")
                        
                        # Verificar componentes clave
                        evaluation = eval_data.get('evaluation', {})
                        if 'dimensional_scores' in evaluation:
                            print("✓ Scores dimensionales incluidos")
                        if 'analysis' in evaluation:
                            print("✓ Análisis incluido")
                        if 'response_details' in evaluation:
                            print("✓ Detalles de respuestas incluidos")
                        
                        return True
                    else:
                        print(f"✗ Error obteniendo detalles: {eval_response.text}")
                        return False
            
            print("✗ No se encontraron coachees con evaluaciones")
            return False
    else:
        print(f"✗ Error obteniendo coachees: {coachees_response.text}")
        return False

if __name__ == "__main__":
    test_coach_login_and_evaluation()
