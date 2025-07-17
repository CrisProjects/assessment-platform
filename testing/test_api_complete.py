#!/usr/bin/env python3
"""
Script para probar directamente los endpoints del API del coach
"""
from app_complete import app, db, User
import json

def test_api_endpoints():
    """Probar endpoints del API directamente"""
    with app.test_client() as client:
        # Simular login del coach
        coach = User.query.filter_by(email='coach@test.com', role='coach').first()
        if not coach:
            print("❌ No se encontró coach de prueba")
            return
        
        print(f"✅ Coach encontrado: {coach.full_name}")
        
        # Simular sesión autenticada
        with client.session_transaction() as sess:
            sess['user_id'] = coach.id
            sess['user_role'] = 'coach'
        
        print("\n🧪 Probando endpoints del API...")
        
        # 1. Probar /api/coach/my-coachees
        print("\n1️⃣ Probando /api/coach/my-coachees")
        response = client.get('/api/coach/my-coachees')
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.get_json()
            print(f"   ✅ Coachees encontrados: {len(data.get('coachees', []))}")
            if data.get('coachees'):
                for coachee in data['coachees']:
                    print(f"      - {coachee['full_name']} ({coachee['email']})")
                    if coachee.get('last_assessment'):
                        print(f"        📊 Última evaluación: {coachee['last_assessment']['score']}%")
        else:
            print(f"   ❌ Error: {response.get_data(as_text=True)}")
        
        # 2. Probar /api/coach/evaluation-summaries
        print("\n2️⃣ Probando /api/coach/evaluation-summaries")
        response = client.get('/api/coach/evaluation-summaries')
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.get_json()
            print(f"   ✅ Resúmenes encontrados: {len(data.get('summaries', []))}")
            if data.get('summaries'):
                for summary in data['summaries']:
                    print(f"      - {summary['coachee_name']}: {summary['latest_score']}%")
                    print(f"        Áreas de enfoque: {', '.join(summary['focus_areas'])}")
                    print(f"        Total evaluaciones: {summary['total_evaluations']}")
        else:
            print(f"   ❌ Error: {response.get_data(as_text=True)}")
        
        # 3. Probar /api/coach/dashboard-stats
        print("\n3️⃣ Probando /api/coach/dashboard-stats")
        response = client.get('/api/coach/dashboard-stats')
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.get_json()
            print(f"   ✅ Estadísticas del dashboard:")
            print(f"      - Total coachees: {data.get('total_coachees', 0)}")
            print(f"      - Total evaluaciones: {data.get('total_assessments', 0)}")
            print(f"      - Puntuación promedio: {data.get('avg_score', 0)}")
            print(f"      - Actividad reciente: {data.get('recent_activity', 0)}")
        else:
            print(f"   ❌ Error: {response.get_data(as_text=True)}")
        
        # 4. Probar /api/coach/tasks
        print("\n4️⃣ Probando /api/coach/tasks")
        response = client.get('/api/coach/tasks')
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.get_json()
            print(f"   ✅ Tareas encontradas: {len(data.get('tasks', []))}")
        else:
            print(f"   ❌ Error: {response.get_data(as_text=True)}")
        
        # 5. Probar endpoint de detalles de evaluación de coachee
        coachees = User.query.filter_by(role='coachee', coach_id=coach.id).all()
        if coachees:
            coachee_id = coachees[0].id
            print(f"\n5️⃣ Probando /api/coach/coachee-evaluation-details/{coachee_id}")
            response = client.get(f'/api/coach/coachee-evaluation-details/{coachee_id}')
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                data = response.get_json()
                if data.get('success'):
                    evaluation = data.get('evaluation', {})
                    print(f"   ✅ Detalles de evaluación obtenidos:")
                    print(f"      - Puntuación: {evaluation.get('total_score')}%")
                    print(f"      - Nivel: {evaluation.get('assertiveness_level')}")
                    print(f"      - Dimensiones: {len(evaluation.get('dimensional_scores', {}))}")
                    print(f"      - Respuestas: {len(evaluation.get('response_details', []))}")
                else:
                    print(f"   ❌ Error en respuesta: {data.get('error')}")
            else:
                print(f"   ❌ Error: {response.get_data(as_text=True)}")

if __name__ == "__main__":
    with app.app_context():
        test_api_endpoints()
