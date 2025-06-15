#!/usr/bin/env python3
"""
Script para crear evaluaciones de muestra para probar el dashboard del coach
"""

import requests
import json
import random

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def create_sample_assessment(username, password, score_range):
    """Crear una evaluación de muestra para un usuario"""
    
    print(f"📝 Creando evaluación para {username}...")
    
    # Login del coachee
    session = requests.Session()
    login_data = {"username": username, "password": password}
    headers = {'Content-Type': 'application/json'}
    
    login_response = session.post(f"{BASE_URL}/api/login", json=login_data, headers=headers)
    
    if login_response.status_code != 200 or not login_response.json().get('success'):
        print(f"   ❌ Error en login de {username}")
        return False
    
    print(f"   ✅ Login exitoso para {username}")
    
    # Crear respuestas simuladas
    # score_range es una tupla (min, max) para simular diferentes niveles
    answers = {}
    
    for i in range(40):  # 40 preguntas
        # Generar respuesta basada en el rango deseado
        if score_range[0] <= 40:  # Poco asertivo
            # Más respuestas pasivas (1) y agresivas (2)
            response = random.choices([1, 2, 3, 4], weights=[40, 30, 20, 10])[0]
        elif score_range[0] <= 60:  # Moderadamente asertivo
            # Distribución más equilibrada
            response = random.choices([1, 2, 3, 4], weights=[20, 25, 35, 20])[0]
        elif score_range[0] <= 80:  # Asertivo
            # Más respuestas asertivas
            response = random.choices([1, 2, 3, 4], weights=[10, 15, 25, 50])[0]
        else:  # Muy asertivo
            # Principalmente respuestas asertivas
            response = random.choices([1, 2, 3, 4], weights=[5, 5, 20, 70])[0]
        
        answers[str(i)] = response
    
    # Enviar evaluación
    assessment_data = {
        'answers': answers,
        'age': random.randint(25, 45),
        'gender': random.choice(['male', 'female'])
    }
    
    response = session.post(f"{BASE_URL}/api/save_assessment", json=assessment_data, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        print(f"   ✅ Evaluación creada: {result.get('total_score')}% ({result.get('assertiveness_level')})")
        return True
    else:
        print(f"   ❌ Error creando evaluación: {response.status_code}")
        print(f"   Respuesta: {response.text}")
        return False

def verify_coach_dashboard():
    """Verificar que el dashboard del coach ahora muestre datos"""
    
    print("\n🎯 Verificando dashboard del coach...")
    
    # Login como coach
    session = requests.Session()
    login_data = {"username": "coach_demo", "password": "coach123"}
    headers = {'Content-Type': 'application/json'}
    
    login_response = session.post(f"{BASE_URL}/api/login", json=login_data, headers=headers)
    
    if login_response.status_code != 200 or not login_response.json().get('success'):
        print("   ❌ Error en login del coach")
        return False
    
    # Verificar estadísticas
    stats_response = session.get(f"{BASE_URL}/api/coach/dashboard-stats")
    
    if stats_response.status_code == 200:
        stats = stats_response.json()
        print("   ✅ Estadísticas del dashboard:")
        print(f"      📊 Coachees: {stats.get('total_coachees', 0)}")
        print(f"      📝 Evaluaciones: {stats.get('total_assessments', 0)}")
        print(f"      🎯 Puntuación promedio: {stats.get('avg_score', 0)}%")
        print(f"      📅 Actividad reciente: {stats.get('recent_activity', 0)}")
        
        if stats.get('total_assessments', 0) > 0:
            print("   ✅ Dashboard del coach con datos!")
            return True
        else:
            print("   ⚠️ Dashboard sin evaluaciones")
            return False
    else:
        print(f"   ❌ Error en estadísticas: {stats_response.status_code}")
        print(f"   Respuesta: {stats_response.text}")
        return False

def main():
    print("🧪 CREANDO EVALUACIONES DE MUESTRA")
    print("=" * 50)
    print(f"URL: {BASE_URL}")
    print()
    
    # Crear varias evaluaciones para el coachee_demo con diferentes niveles
    evaluations_created = 0
    
    # Evaluación 1: Poco asertivo
    if create_sample_assessment("coachee_demo", "coachee123", (30, 50)):
        evaluations_created += 1
    
    # Evaluación 2: Moderadamente asertivo
    if create_sample_assessment("coachee_demo", "coachee123", (50, 70)):
        evaluations_created += 1
    
    # Evaluación 3: Asertivo
    if create_sample_assessment("coachee_demo", "coachee123", (70, 85)):
        evaluations_created += 1
    
    print(f"\n📊 Evaluaciones creadas: {evaluations_created}")
    
    # Verificar que el dashboard del coach ahora funcione
    dashboard_ok = verify_coach_dashboard()
    
    print("\n" + "=" * 50)
    print("📋 RESUMEN:")
    print("=" * 50)
    
    if evaluations_created > 0 and dashboard_ok:
        print("🎉 ¡DASHBOARD DEL COACH FUNCIONANDO CON DATOS!")
        print()
        print("✅ Evaluaciones de muestra creadas")
        print("✅ Estadísticas del dashboard funcionando")
        print("✅ Datos mostrados correctamente")
        print()
        print("🎯 PUEDES ACCEDER AHORA:")
        print(f"   URL: {BASE_URL}/login")
        print("   Usuario: coach_demo")
        print("   Password: coach123")
        print()
        print("📊 El dashboard ahora mostrará:")
        print("   - Número de coachees")
        print("   - Total de evaluaciones")
        print("   - Puntuación promedio")
        print("   - Gráficos de distribución")
    else:
        print("❌ Problemas creando evaluaciones o verificando dashboard")

if __name__ == "__main__":
    main()
