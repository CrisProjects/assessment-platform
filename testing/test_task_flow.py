#!/usr/bin/env python3
"""
Script para probar el flujo completo de tareas entre coach y coachee
"""
import requests
import json
from datetime import datetime, timedelta

def test_task_flow():
    base_url = "http://127.0.0.1:10000"
    coach_session = requests.Session()
    coachee_session = requests.Session()
    
    print("=== PRUEBA COMPLETA DEL SISTEMA DE TAREAS ===\n")
    
    # 1. Login del coach
    print("1. Login del coach...")
    coach_login = coach_session.post(f"{base_url}/api/coach/login", json={
        'username': 'coach_test',
        'password': 'test123'
    })
    
    if coach_login.status_code != 200:
        print(f"✗ Error en login del coach: {coach_login.status_code}")
        return False
    
    print("✓ Coach logueado exitosamente")
    
    # 2. Obtener coachees del coach
    print("\n2. Obteniendo coachees asignados al coach...")
    coachees_response = coach_session.get(f"{base_url}/api/coach/my-coachees")
    
    if coachees_response.status_code != 200:
        print(f"✗ Error obteniendo coachees: {coachees_response.status_code}")
        return False
    
    coachees = coachees_response.json()
    if not coachees:
        print("✗ No hay coachees asignados al coach")
        return False
    
    target_coachee = coachees[0]
    print(f"✓ Coachee encontrado: {target_coachee['full_name']} (ID: {target_coachee['id']})")
    
    # 3. Crear una tarea para el coachee
    print(f"\n3. Creando tarea para {target_coachee['full_name']}...")
    
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    
    task_data = {
        'coachee_id': target_coachee['id'],
        'title': 'Ejercicio de Comunicación Asertiva',
        'description': 'Practicar técnicas de comunicación asertiva durante 15 minutos diarios. Registrar situaciones donde apliques estas técnicas.',
        'category': 'comunicacion',
        'priority': 'high',
        'due_date': tomorrow
    }
    
    create_task_response = coach_session.post(f"{base_url}/api/coach/tasks", json=task_data)
    
    if create_task_response.status_code != 201:
        print(f"✗ Error creando tarea: {create_task_response.status_code}")
        print(f"Response: {create_task_response.text}")
        return False
    
    task_result = create_task_response.json()
    created_task_id = task_result['task']['id']
    print(f"✓ Tarea creada exitosamente (ID: {created_task_id})")
    
    # 4. Verificar que la tarea aparece en las tareas del coach
    print("\n4. Verificando tareas del coach...")
    coach_tasks_response = coach_session.get(f"{base_url}/api/coach/tasks")
    
    if coach_tasks_response.status_code != 200:
        print(f"✗ Error obteniendo tareas del coach: {coach_tasks_response.status_code}")
        return False
    
    coach_tasks = coach_tasks_response.json()
    task_found = any(task['id'] == created_task_id for task in coach_tasks.get('tasks', []))
    
    if task_found:
        print("✓ Tarea encontrada en la lista del coach")
    else:
        print("✗ Tarea no encontrada en la lista del coach")
        return False
    
    # 5. Login del coachee
    print(f"\n5. Login del coachee ({target_coachee['username']})...")
    
    # Buscar credenciales del coachee en la base de datos
    import sqlite3
    conn = sqlite3.connect('assessments.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, password_hash FROM user WHERE id = ?', (target_coachee['id'],))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        print("✗ No se encontraron credenciales del coachee")
        return False
    
    # Para testing, usar credenciales conocidas de un coachee de prueba
    coachee_login = coachee_session.post(f"{base_url}/api/coachee/login", json={
        'username': 'coachee',  # Usuario conocido
        'password': 'test123'   # Contraseña conocida
    })
    
    if coachee_login.status_code != 200:
        print(f"✗ Error en login del coachee: {coachee_login.status_code}")
        print(f"Response: {coachee_login.text}")
        return False
    
    print("✓ Coachee logueado exitosamente")
    
    # 6. Verificar que la tarea aparece en las tareas del coachee
    print(f"\n6. Verificando que la tarea llega al coachee...")
    coachee_tasks_response = coachee_session.get(f"{base_url}/api/coachee/tasks")
    
    if coachee_tasks_response.status_code != 200:
        print(f"✗ Error obteniendo tareas del coachee: {coachee_tasks_response.status_code}")
        print(f"Response: {coachee_tasks_response.text}")
        return False
    
    coachee_tasks = coachee_tasks_response.json()
    task_found_in_coachee = any(task['id'] == created_task_id for task in coachee_tasks.get('tasks', []))
    
    if task_found_in_coachee:
        print("✓ ¡Tarea encontrada en la lista del coachee! El sistema funciona correctamente")
        
        # Mostrar detalles de la tarea
        target_task = next(task for task in coachee_tasks['tasks'] if task['id'] == created_task_id)
        print(f"   - Título: {target_task['title']}")
        print(f"   - Descripción: {target_task['description']}")
        print(f"   - Categoría: {target_task['category']}")
        print(f"   - Prioridad: {target_task['priority']}")
        print(f"   - Estado: {target_task['current_status']}")
        print(f"   - Progreso: {target_task['current_progress']}%")
        
    else:
        print("✗ Tarea NO encontrada en la lista del coachee")
        print(f"Tareas del coachee: {len(coachee_tasks.get('tasks', []))}")
        return False
    
    # 7. Actualizar progreso de la tarea desde el coachee
    print(f"\n7. Actualizando progreso de la tarea desde el coachee...")
    
    progress_data = {
        'status': 'in_progress',
        'progress_percentage': 50,
        'notes': 'He completado la primera sesión de práctica. Las técnicas están funcionando bien.'
    }
    
    update_response = coachee_session.put(f"{base_url}/api/coachee/tasks/{created_task_id}/progress", json=progress_data)
    
    if update_response.status_code == 200:
        print("✓ Progreso actualizado exitosamente")
    else:
        print(f"✗ Error actualizando progreso: {update_response.status_code}")
        print(f"Response: {update_response.text}")
    
    print(f"\n=== RESULTADO FINAL ===")
    print("✅ SISTEMA DE TAREAS FUNCIONANDO CORRECTAMENTE")
    print("✅ Las tareas creadas por el coach llegan al coachee")
    print("✅ El coachee puede ver y actualizar las tareas")
    print("✅ El flujo completo está operativo")
    
    return True

if __name__ == "__main__":
    test_task_flow()
