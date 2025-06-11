#!/usr/bin/env python3
"""
Script para probar el flujo de login automático en el frontend
"""
import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_frontend_flow():
    """Simula el flujo que hace el frontend: registro + obtener preguntas"""
    session = requests.Session()
    
    print("🔄 Probando flujo de frontend completo...")
    
    # 1. Simular login automático como hace el frontend ahora
    print("\n1. Login automático como admin...")
    login_response = session.post(f"{BASE_URL}/api/login", json={
        "username": "admin",
        "password": "admin123"
    })
    
    if login_response.status_code == 200:
        print("✅ Login automático exitoso")
    else:
        print(f"❌ Error en login automático: {login_response.status_code}")
        return False
    
    # 2. Simular registro de usuario (datos demográficos)
    print("\n2. Registro de datos demográficos...")
    register_response = session.post(f"{BASE_URL}/api/register", json={
        "name": "Usuario de Prueba",
        "email": "prueba@test.com", 
        "age": 25,
        "gender": "masculino"
    })
    
    print(f"Status de registro: {register_response.status_code}")
    if register_response.status_code not in [200, 201]:
        print(f"⚠️ Registro no fue exitoso pero continuamos: {register_response.text}")
    
    # 3. Obtener preguntas (con autenticación)
    print("\n3. Obteniendo preguntas con autenticación...")
    questions_response = session.get(f"{BASE_URL}/api/questions")
    
    if questions_response.status_code == 200:
        questions_data = questions_response.json()
        questions = questions_data.get('questions', [])
        print(f"✅ Preguntas obtenidas exitosamente")
        print(f"   Cantidad: {len(questions)}")
        if questions:
            print(f"   Primera pregunta: {questions[0]['content'][:50]}...")
        return True
    else:
        print(f"❌ Error obteniendo preguntas: {questions_response.status_code}")
        print(f"   Respuesta: {questions_response.text}")
        return False

if __name__ == "__main__":
    success = test_frontend_flow()
    if success:
        print("\n✅ FLUJO DE FRONTEND EXITOSO - La aplicación debería funcionar ahora")
    else:
        print("\n❌ FLUJO DE FRONTEND FALLIDO - Aún hay problemas")
