#!/usr/bin/env python3
"""
Script completo para probar el dashboard del coach con autenticación
"""
import requests
import json

def test_coach_functionality():
    """Probar funcionamiento completo del coach con login"""
    base_url = "http://127.0.0.1:10000"
    session = requests.Session()
    
    print("=== PRUEBA COMPLETA DEL DASHBOARD DEL COACH ===\n")
    
    # 1. Login del coach
    print("1. Intentando login como coach...")
    login_data = {
        "username": "coach_test",
        "password": "test123"
    }
    
    response = session.post(f"{base_url}/api/coach/login", json=login_data)
    print(f"   Status del login: {response.status_code}")
    
    if response.status_code != 200:
        print(f"   Error en login: {response.text}")
        print("   Saltando pruebas que requieren autenticación.")
        return
    
    print("   ✅ Login exitoso!")
    login_result = response.json()
    print(f"   Usuario logueado: {login_result.get('user', {}).get('full_name', 'N/A')}")
    
    # 2. Obtener lista de coachees
    print("\n2. Obteniendo lista de coachees...")
    response = session.get(f"{base_url}/api/coach/my-coachees")
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        coachees = data.get('coachees', [])
        print(f"   ✅ Coachees encontrados: {len(coachees)}")
        
        if coachees:
            for i, coachee in enumerate(coachees[:3]):  # Solo mostrar los primeros 3
                print(f"   {i+1}. {coachee.get('full_name', 'N/A')} - ID: {coachee.get('id', 'N/A')}")
                print(f"      Email: {coachee.get('email', 'N/A')}")
                print(f"      Evaluaciones: {coachee.get('total_assessments', 0)}")
                print(f"      Última evaluación: {coachee.get('last_assessment_date', 'N/A')}")
                
            # 3. Probar análisis detallado del primer coachee
            first_coachee = coachees[0]
            coachee_id = first_coachee.get('id')
            
            if coachee_id:
                print(f"\n3. Probando análisis detallado del coachee: {first_coachee.get('full_name', 'N/A')}")
                
                # Resumen de evaluación
                response = session.get(f"{base_url}/api/coach/evaluation-summary/{coachee_id}")
                print(f"   Status del resumen: {response.status_code}")
                
                if response.status_code == 200:
                    summary = response.json()
                    summary_data = summary.get('summary', {})
                    
                    print(f"   ✅ Resumen obtenido:")
                    print(f"   - Total de evaluaciones: {summary_data.get('total_assessments', 0)}")
                    print(f"   - Tendencia de progreso: {summary_data.get('progress_trend', 'N/A')}")
                    print(f"   - Fortalezas: {len(summary_data.get('strengths', []))}")
                    print(f"   - Áreas de mejora: {len(summary_data.get('improvement_areas', []))}")
                    print(f"   - Recomendaciones: {len(summary_data.get('recommendations', []))}")
                    
                    # Probar detalles de evaluación específica
                    latest = summary_data.get('latest_assessment')
                    if latest and latest.get('id'):
                        evaluation_id = latest['id']
                        print(f"\n4. Probando detalles de evaluación específica (ID: {evaluation_id})...")
                        
                        response = session.get(f"{base_url}/api/coach/evaluation-details/{evaluation_id}")
                        print(f"   Status del detalle: {response.status_code}")
                        
                        if response.status_code == 200:
                            detail = response.json()
                            evaluation = detail.get('evaluation', {})
                            
                            print(f"   ✅ Detalles obtenidos:")
                            print(f"   - Fecha: {evaluation.get('completion_date', 'N/A')}")
                            print(f"   - Puntuación total: {evaluation.get('total_score', 'N/A')}")
                            print(f"   - Nivel de asertividad: {evaluation.get('assertiveness_level', 'N/A')}")
                            
                            # Análisis completo
                            analysis = evaluation.get('analysis', {})
                            if analysis:
                                print(f"   - Análisis completo disponible: ✅")
                                print(f"     * Fortalezas: {len(analysis.get('strengths', []))}")
                                print(f"     * Áreas de mejora: {len(analysis.get('improvement_areas', []))}")
                                print(f"     * Recomendaciones: {len(analysis.get('recommendations', []))}")
                                
                                # Scores dimensionales
                                scores = analysis.get('dimensional_scores', {})
                                if scores:
                                    print(f"     * Scores dimensionales:")
                                    for dim, score in scores.items():
                                        print(f"       - {dim}: {score}")
                            else:
                                print(f"   - Análisis completo: ❌ No disponible")
                        else:
                            print(f"   ❌ Error obteniendo detalles: {response.text}")
                    else:
                        print("   ⚠️ No hay evaluaciones disponibles para mostrar detalles")
                else:
                    print(f"   ❌ Error obteniendo resumen: {response.text}")
        else:
            print("   ⚠️ No hay coachees asignados")
    else:
        print(f"   ❌ Error obteniendo coachees: {response.text}")
    
    # 5. Probar gestión de tareas
    print(f"\n5. Probando gestión de tareas...")
    response = session.get(f"{base_url}/api/coach/tasks")
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        tasks = data.get('tasks', [])
        print(f"   ✅ Tareas encontradas: {len(tasks)}")
        
        for i, task in enumerate(tasks[:3]):  # Solo mostrar las primeras 3
            print(f"   {i+1}. {task.get('title', 'N/A')} - Estado: {task.get('current_status', 'N/A')}")
    else:
        print(f"   ❌ Error obteniendo tareas: {response.text}")
    
    print(f"\n=== PRUEBA COMPLETADA ===")

if __name__ == "__main__":
    test_coach_functionality()
