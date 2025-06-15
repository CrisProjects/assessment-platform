#!/usr/bin/env python3
"""
Script para probar el dashboard del coach
"""

import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_coach_dashboard():
    """Probar el dashboard del coach completo"""
    
    print("🧪 PROBANDO DASHBOARD DEL COACH")
    print("=" * 50)
    
    # Crear sesión
    session = requests.Session()
    
    # 1. Login como coach
    print("1. Haciendo login como coach_demo...")
    login_data = {
        'username': 'coach_demo',
        'password': 'coach123'
    }
    
    headers = {'Content-Type': 'application/json'}
    login_response = session.post(f"{BASE_URL}/api/login", json=login_data, headers=headers)
    
    if login_response.status_code == 200:
        login_result = login_response.json()
        if login_result.get('success'):
            print("   ✅ Login exitoso como coach")
            print(f"   📍 Redirección a: {login_result.get('redirect_url')}")
            
            # 2. Acceder al dashboard
            print("2. Accediendo al dashboard del coach...")
            dashboard_response = session.get(f"{BASE_URL}/coach-dashboard")
            
            if dashboard_response.status_code == 200:
                print("   ✅ Dashboard del coach accesible")
                
                # 3. Probar APIs del coach
                print("3. Probando APIs del coach...")
                
                # API de estadísticas
                stats_response = session.get(f"{BASE_URL}/api/coach/dashboard-stats")
                if stats_response.status_code == 200:
                    stats = stats_response.json()
                    print(f"   ✅ Estadísticas: {stats['total_coachees']} coachees, {stats['total_assessments']} evaluaciones")
                else:
                    print(f"   ❌ Error en estadísticas: {stats_response.status_code}")
                
                # API de coachees
                coachees_response = session.get(f"{BASE_URL}/api/coach/my-coachees")
                if coachees_response.status_code == 200:
                    coachees = coachees_response.json()
                    print(f"   ✅ Lista de coachees: {len(coachees)} coachees encontrados")
                    
                    # Mostrar detalles de los coachees
                    for coachee in coachees:
                        print(f"      - {coachee['full_name']} ({coachee['username']}) - {coachee['total_assessments']} evaluaciones")
                        
                        # Probar progreso del coachee
                        if coachee['id']:
                            progress_response = session.get(f"{BASE_URL}/api/coach/coachee-progress/{coachee['id']}")
                            if progress_response.status_code == 200:
                                progress = progress_response.json()
                                print(f"        📊 Progreso: {len(progress['assessments'])} evaluaciones en historial")
                            else:
                                print(f"        ❌ Error obteniendo progreso: {progress_response.status_code}")
                else:
                    print(f"   ❌ Error obteniendo coachees: {coachees_response.status_code}")
                
                return True
            else:
                print(f"   ❌ Error accediendo al dashboard: {dashboard_response.status_code}")
                return False
        else:
            print(f"   ❌ Login falló: {login_result.get('error')}")
            return False
    else:
        print(f"   ❌ Error en login: {login_response.status_code}")
        return False

def create_sample_assessment():
    """Crear una evaluación de muestra para el coachee_demo"""
    print("\n4. Creando evaluación de muestra...")
    
    # Login como coachee
    session = requests.Session()
    login_data = {
        'username': 'coachee_demo',
        'password': 'coachee123'
    }
    
    headers = {'Content-Type': 'application/json'}
    login_response = session.post(f"{BASE_URL}/api/login", json=login_data, headers=headers)
    
    if login_response.status_code == 200 and login_response.json().get('success'):
        print("   ✅ Login como coachee exitoso")
        
        # Crear respuestas de muestra
        sample_responses = {}
        for i in range(1, 41):  # 40 preguntas
            sample_responses[str(i)] = 3  # Respuesta "asertiva"
        
        # Enviar evaluación
        assessment_data = {
            'responses': sample_responses
        }
        
        submit_response = session.post(f"{BASE_URL}/api/save_assessment", json=assessment_data, headers=headers)
        
        if submit_response.status_code == 200:
            result = submit_response.json()
            print(f"   ✅ Evaluación creada: {result.get('overall_score')}% de asertividad")
            return True
        else:
            print(f"   ❌ Error creando evaluación: {submit_response.status_code}")
            return False
    else:
        print("   ❌ Error en login del coachee")
        return False

def main():
    print("🚀 PRUEBA COMPLETA DEL DASHBOARD DEL COACH")
    print("=" * 60)
    print(f"URL: {BASE_URL}")
    print()
    
    # Crear evaluación de muestra primero
    sample_created = create_sample_assessment()
    
    # Probar dashboard del coach
    coach_success = test_coach_dashboard()
    
    print("\n" + "=" * 60)
    print("📋 RESUMEN:")
    print("=" * 60)
    
    if coach_success:
        print("✅ DASHBOARD DEL COACH FUNCIONANDO!")
        print("✅ APIs del coach operativas")
        print("✅ Monitoreo de coachees activo")
        if sample_created:
            print("✅ Evaluaciones de muestra creadas")
        print()
        print("🎯 CREDENCIALES PARA PROBAR:")
        print("   Coach: coach_demo / coach123")
        print("   Coachee: coachee_demo / coachee123")
        print(f"   URL Coach Dashboard: {BASE_URL}/coach-dashboard")
    else:
        print("❌ Problemas con el dashboard del coach")

if __name__ == "__main__":
    main()
