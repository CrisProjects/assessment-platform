#!/usr/bin/env python3
"""
Script para diagnosticar la base de datos en producción
"""

import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_production_database():
    """Probar la base de datos en producción"""
    print("🔍 Diagnosticando base de datos en producción...")
    
    # 1. Verificar que el servidor esté funcionando
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        if response.status_code == 200:
            print("✅ Servidor funcionando correctamente")
        else:
            print(f"⚠️ Servidor responde con código: {response.status_code}")
    except Exception as e:
        print(f"❌ Error conectando al servidor: {e}")
        return False
    
    # 2. Probar login con diferentes usuarios
    test_users = [
        {'username': 'admin', 'password': 'admin123'},
        {'username': 'coach_demo', 'password': 'coach123'},
        {'username': 'coachee_demo', 'password': 'coachee123'}
    ]
    
    for user in test_users:
        print(f"\n🔐 Probando login: {user['username']}")
        try:
            response = requests.post(
                f"{BASE_URL}/api/login",
                json=user,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    print(f"   ✅ Login exitoso: {result.get('user', {}).get('role', 'sin rol')}")
                else:
                    print(f"   ❌ Login falló: {result.get('error', 'error desconocido')}")
            else:
                try:
                    error_data = response.json()
                    print(f"   ❌ Error HTTP {response.status_code}: {error_data.get('error', response.text)}")
                except:
                    print(f"   ❌ Error HTTP {response.status_code}: {response.text}")
                    
        except Exception as e:
            print(f"   💥 Excepción: {e}")
    
    # 3. Probar endpoint de evaluaciones sin autenticación
    print(f"\n📊 Probando endpoint de evaluaciones...")
    try:
        response = requests.get(f"{BASE_URL}/api/assessments", timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 401:
            print("   ✅ Autenticación requerida (comportamiento esperado)")
        elif response.status_code == 200:
            data = response.json()
            print(f"   ✅ Evaluaciones disponibles: {len(data.get('assessments', []))}")
        else:
            print(f"   ⚠️ Respuesta inesperada: {response.text[:200]}")
    except Exception as e:
        print(f"   💥 Error: {e}")

if __name__ == '__main__':
    test_production_database()
