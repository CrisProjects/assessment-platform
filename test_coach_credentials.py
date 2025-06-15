#!/usr/bin/env python3
"""
Script para verificar las credenciales específicas del coach
"""

import requests
import json

BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def test_coach_credentials():
    """Probar específicamente las credenciales del coach"""
    
    print("🎯 VERIFICANDO CREDENCIALES DEL COACH")
    print("=" * 50)
    
    # Probar login del coach
    login_data = {
        'username': 'coach_demo',
        'password': 'coach123'
    }
    
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(f"{BASE_URL}/api/login", json=login_data, headers=headers, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Respuesta: {json.dumps(result, indent=2)}")
            
            if result.get('success'):
                print("✅ LOGIN EXITOSO DEL COACH")
                print(f"👤 Usuario: {result['user']['full_name']}")
                print(f"🎯 Rol: {result['user']['role']}")
                print(f"📍 Redirección: {result['redirect_url']}")
                
                # Probar acceso al dashboard
                session = requests.Session()
                # Hacer login para mantener sesión
                session.post(f"{BASE_URL}/api/login", json=login_data, headers=headers)
                
                dashboard_response = session.get(f"{BASE_URL}/coach-dashboard")
                print(f"Dashboard Status: {dashboard_response.status_code}")
                
                if dashboard_response.status_code == 200:
                    print("✅ DASHBOARD DEL COACH ACCESIBLE")
                    return True
                else:
                    print(f"❌ Error accediendo al dashboard: {dashboard_response.status_code}")
                    return False
            else:
                print(f"❌ LOGIN FALLÓ: {result.get('error')}")
                return False
        else:
            print(f"❌ Error HTTP: {response.status_code}")
            print(f"Respuesta: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error de conexión: {str(e)}")
        return False

def show_current_users():
    """Mostrar usuarios actuales en el sistema"""
    
    print("\n👥 USUARIOS ACTUALES EN EL SISTEMA")
    print("=" * 50)
    
    try:
        response = requests.get(f"{BASE_URL}/api/debug-users", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"Total de usuarios: {data['user_count']}")
            
            for user in data['users']:
                print(f"  👤 {user['username']} ({user['full_name']})")
                print(f"      📧 {user['email']}")
                print(f"      🎯 Rol: {user['role']}")
                print(f"      ✅ Activo: {'Sí' if user['is_active'] else 'No'}")
                print()
        else:
            print(f"❌ Error obteniendo usuarios: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error de conexión: {str(e)}")

def main():
    print("🔍 DIAGNÓSTICO DE CREDENCIALES")
    print("=" * 60)
    print(f"URL: {BASE_URL}")
    print()
    
    # Mostrar usuarios actuales
    show_current_users()
    
    # Probar credenciales del coach
    coach_success = test_coach_credentials()
    
    print("\n" + "=" * 60)
    print("📋 RESULTADO:")
    print("=" * 60)
    
    if coach_success:
        print("🎉 ¡CREDENCIALES DEL COACH FUNCIONANDO!")
        print()
        print("🎯 CREDENCIALES CONFIRMADAS:")
        print("   Usuario: coach_demo")
        print("   Password: coach123")
        print("   Rol: coach")
        print()
        print(f"🌐 ACCEDER EN: {BASE_URL}/login")
        print("   Usar las credenciales del coach para acceder al dashboard")
    else:
        print("❌ Problemas con las credenciales del coach")
        print("   Revisar configuración o reinicializar usuarios")

if __name__ == "__main__":
    main()
