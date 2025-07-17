#!/usr/bin/env python3
"""
Script para crear una página de prueba del dashboard del coach
"""
import requests

def create_test_page():
    session = requests.Session()
    
    # Login del coach
    login_response = session.post('http://127.0.0.1:10000/api/coach/login', json={
        'username': 'coach_test',
        'password': 'test123'
    })
    
    if login_response.status_code != 200:
        print("Error en login del coach")
        return
    
    # Obtener coachees
    coachees_response = session.get('http://127.0.0.1:10000/api/coach/my-coachees')
    
    if coachees_response.status_code != 200:
        print("Error obteniendo coachees")
        return
    
    coachees_data = coachees_response.json()
    print(f"Coachees disponibles: {len(coachees_data)}")
    
    for coachee in coachees_data:
        print(f"\nCoachee: {coachee['full_name']}")
        print(f"  ID: {coachee['id']}")
        print(f"  Total evaluaciones: {coachee.get('total_assessments', 0)}")
        
        if coachee.get('last_assessment'):
            print(f"  Última evaluación - Score: {coachee['last_assessment']['score']}")
            
            # Probar endpoint de detalle
            detail_response = session.get(f"http://127.0.0.1:10000/api/coach/coachee-evaluation-details/{coachee['id']}")
            
            if detail_response.status_code == 200:
                detail_data = detail_response.json()
                evaluation = detail_data.get('evaluation', {})
                print(f"  ✓ Detalle obtenido - Score total: {evaluation.get('total_score', evaluation.get('score', 'N/A'))}")
                print(f"  ✓ Nivel de asertividad: {evaluation.get('assertiveness_level', 'N/A')}")
                
                # Verificar componentes clave
                if evaluation.get('dimensional_scores'):
                    print(f"  ✓ Scores dimensionales: {len(evaluation['dimensional_scores'])} dimensiones")
                if evaluation.get('analysis'):
                    analysis = evaluation['analysis']
                    print(f"  ✓ Análisis - Fortalezas: {len(analysis.get('strengths', []))}, Mejoras: {len(analysis.get('improvements', []))}")
                if evaluation.get('response_details'):
                    print(f"  ✓ Detalles de respuestas: {len(evaluation['response_details'])} respuestas")
            else:
                print(f"  ✗ Error obteniendo detalle: {detail_response.status_code}")
        else:
            print("  Sin evaluaciones")

if __name__ == "__main__":
    create_test_page()
