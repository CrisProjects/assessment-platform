#!/usr/bin/env python3
"""
Script para probar acceso al dashboard con diferentes usuarios
"""
import requests
import json
import time

def test_login_and_dashboard(username, password, base_url="https://assessment-platform-1nuo.onrender.com"):
    """Prueba login y acceso al dashboard con credenciales específicas"""
    print(f"\n🔐 Probando login con {username}/*****")
    print("-" * 40)
    
    session = requests.Session()
    
    # 1. Probar login
    try:
        login_response = session.post(
            f"{base_url}/api/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        
        print(f"   Login Status: {login_response.status_code}")
        
        if login_response.status_code == 200:
            data = login_response.json()
            if data.get('success'):
                user_info = data.get('user', {})
                print(f"   ✅ Login exitoso!")
                print(f"   📧 Email: {user_info.get('email', 'N/A')}")
                print(f"   👤 Nombre: {user_info.get('full_name', 'N/A')}")
                print(f"   🏷️ Rol: {user_info.get('role', 'N/A')}")
                print(f"   🔐 Admin: {user_info.get('is_platform_admin', False)}")
                
                # 2. Intentar acceder al dashboard de admin
                print(f"\n   🎯 Probando acceso al dashboard admin...")
                dashboard_response = session.get(f"{base_url}/platform-admin-dashboard")
                print(f"   Dashboard Status: {dashboard_response.status_code}")
                
                if dashboard_response.status_code == 200:
                    if "Dashboard Admin - En construcción" in dashboard_response.text:
                        print("   ⚠️ Dashboard muestra 'En construcción'")
                    elif "admin_dashboard.html" in dashboard_response.text or "Administrador" in dashboard_response.text:
                        print("   ✅ Dashboard cargando correctamente!")
                    else:
                        print("   🔍 Dashboard carga pero contenido desconocido")
                        print(f"   📄 Primeros 200 chars: {dashboard_response.text[:200]}")
                elif dashboard_response.status_code == 403:
                    print("   ❌ Acceso denegado al dashboard")
                elif dashboard_response.status_code == 302:
                    redirect_url = dashboard_response.headers.get('Location', 'Unknown')
                    print(f"   🔄 Redirigido a: {redirect_url}")
                else:
                    print(f"   ❌ Error accediendo al dashboard: {dashboard_response.status_code}")
                    
                return True
            else:
                print(f"   ❌ Login falló: {data.get('error', 'Unknown error')}")
        else:
            print(f"   ❌ Error HTTP: {login_response.text[:100]}")
            
    except Exception as e:
        print(f"   ❌ Error de conexión: {e}")
    
    return False

def test_all_users():
    """Prueba todos los usuarios disponibles"""
    print("🚀 PROBANDO ACCESO AL DASHBOARD ADMIN")
    print("=" * 60)
    
    users_to_test = [
        ("admin", "admin123"),
        ("platform_admin", "admin123"),
        ("coach_demo", "coach123"),
        ("coachee_demo", "coachee123")
    ]
    
    successful_logins = []
    
    for username, password in users_to_test:
        if test_login_and_dashboard(username, password):
            successful_logins.append(username)
        time.sleep(1)  # Pequeña pausa entre requests
    
    print(f"\n📊 RESUMEN:")
    print(f"   ✅ Logins exitosos: {successful_logins}")
    print(f"   📝 Total usuarios probados: {len(users_to_test)}")
    
    if "admin" in successful_logins or "platform_admin" in successful_logins:
        print(f"\n🎯 RECOMENDACIÓN:")
        if "admin" in successful_logins:
            print(f"   Usar: admin / admin123")
        else:
            print(f"   Usar: platform_admin / admin123")
    else:
        print(f"\n⚠️ NINGÚN USUARIO ADMIN FUNCIONA")
        print(f"   Puede ser necesario reinicializar la base de datos")

if __name__ == "__main__":
    test_all_users()
