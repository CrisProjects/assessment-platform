#!/usr/bin/env python3
"""
Script para probar las APIs del coachee
"""
import requests
import json

# URL base
BASE_URL = "http://localhost:5003"

def test_coachee_apis():
    # Crear sesión para mantener cookies
    session = requests.Session()
    
    print("🔐 Realizando login del coachee...")
    
    # Login
    login_response = session.post(f"{BASE_URL}/api/login", json={
        "username": "coachee@assessment.com",
        "password": "coachee123"
    })
    
    if login_response.status_code == 200:
        print("✅ Login exitoso")
        print(f"Usuario: {login_response.json()['user']['full_name']}")
    else:
        print(f"❌ Error en login: {login_response.status_code}")
        return
    
    # Probar API de evaluaciones
    print("\n📊 Probando API de evaluaciones...")
    eval_response = session.get(f"{BASE_URL}/api/coachee/evaluations")
    print(f"Status: {eval_response.status_code}")
    if eval_response.status_code == 200:
        evaluations = eval_response.json()
        print(f"✅ Evaluaciones encontradas: {len(evaluations)}")
        for eval in evaluations:
            print(f"  - Score: {eval['score']}, Fecha: {eval['completed_at'][:10]}")
    else:
        print(f"❌ Error: {eval_response.text}")
    
    # Probar API de tareas
    print("\n📋 Probando API de tareas...")
    tasks_response = session.get(f"{BASE_URL}/api/coachee/tasks")
    print(f"Status: {tasks_response.status_code}")
    if tasks_response.status_code == 200:
        tasks = tasks_response.json()
        print(f"✅ Tareas encontradas: {len(tasks)}")
        for task in tasks:
            print(f"  - {task['title']} ({task['category']}) - {task['status']}")
    else:
        print(f"❌ Error: {tasks_response.text}")
    
    # Probar API de resumen del dashboard
    print("\n📈 Probando API de resumen del dashboard...")
    summary_response = session.get(f"{BASE_URL}/api/coachee/dashboard-summary")
    print(f"Status: {summary_response.status_code}")
    if summary_response.status_code == 200:
        summary = summary_response.json()
        print("✅ Resumen obtenido:")
        print(f"  - Evaluaciones completadas: {summary.get('evaluations_completed', 0)}")
        print(f"  - Tareas activas: {summary.get('active_tasks', 0)}")
        print(f"  - Último score: {summary.get('latest_score', 'N/A')}")
    else:
        print(f"❌ Error: {summary_response.text}")

if __name__ == "__main__":
    test_coachee_apis()
