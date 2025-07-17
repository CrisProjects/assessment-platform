#!/usr/bin/env python3
"""
Script para probar el botón "Invitar Coachee" del dashboard del coach
incluyendo el proceso de login
"""

import requests
import json
import time

def test_invitation_with_login():
    """Probar el botón de invitación con login incluido"""
    base_url = "http://127.0.0.1:5002"
    
    print("🧪 Probando el botón 'Invitar Coachee' con login...")
    
    # Crear una sesión para mantener cookies
    session = requests.Session()
    
    # 1. Hacer login como coach
    print("\n1️⃣ Haciendo login como coach...")
    try:
        # Primero obtener la página de login para obtener CSRF token si es necesario
        login_page = session.get(f"{base_url}/coach-login")
        
        # Hacer login
        login_data = {
            'username': 'coach@assessment.com',
            'password': 'coach123'
        }
        
        login_response = session.post(f"{base_url}/api/coach/login", 
                                    json=login_data,
                                    headers={'Content-Type': 'application/json'})
        
        if login_response.status_code == 200:
            if 'Dashboard Coach' in login_response.text or '/coach-dashboard' in login_response.url:
                print("✅ Login exitoso como coach")
            else:
                print("❌ Login falló - credenciales incorrectas o redirección inesperada")
                print(f"URL final: {login_response.url}")
                return False
        else:
            print(f"❌ Error en login: {login_response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error en login: {e}")
        return False
    
    # 2. Acceder al dashboard del coach
    print("\n2️⃣ Accediendo al dashboard del coach...")
    try:
        dashboard_response = session.get(f"{base_url}/coach-dashboard")
        
        if dashboard_response.status_code == 200:
            print("✅ Dashboard del coach carga correctamente")
            
            dashboard_html = dashboard_response.text
            
            # Verificar que el botón esté presente
            if 'Invitar Coachee' in dashboard_html:
                print("✅ Botón 'Invitar Coachee' encontrado en el HTML")
                
                # Verificar que tenga el onclick correcto
                if 'onclick="openInvitationModal()"' in dashboard_html:
                    print("✅ Función openInvitationModal() correctamente vinculada")
                else:
                    print("❌ Función onclick no encontrada o incorrecta")
            else:
                print("❌ Botón 'Invitar Coachee' NO encontrado en el HTML")
                
            # Verificar que la función JavaScript esté presente
            if 'function openInvitationModal()' in dashboard_html:
                print("✅ Función openInvitationModal() encontrada en JavaScript")
            else:
                print("❌ Función openInvitationModal() NO encontrada")
                
            # Verificar que el modal esté presente
            if 'id="invitationModal"' in dashboard_html:
                print("✅ Modal de invitación encontrado en el HTML")
            else:
                print("❌ Modal de invitación NO encontrado en el HTML")
                
            # Verificar función showToast
            if 'function showToast(' in dashboard_html:
                print("✅ Función showToast encontrada")
            else:
                print("❌ Función showToast NO encontrada")
                
        else:
            print(f"❌ Error al cargar dashboard: {dashboard_response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accediendo al dashboard: {e}")
        return False
    
    # 3. Verificar que el endpoint de API existe
    print("\n3️⃣ Verificando endpoint de API...")
    try:
        # Hacer una prueba de invitación
        api_response = session.post(f"{base_url}/api/coach/invite-coachee", 
                                   json={"email": "test@test.com", "full_name": "Test User"})
        
        if api_response.status_code == 200:
            print("✅ Endpoint /api/coach/invite-coachee funciona correctamente")
        elif api_response.status_code == 400:
            result = api_response.json()
            print(f"✅ Endpoint existe, validación funciona: {result.get('error', 'Error de validación')}")
        elif api_response.status_code == 404:
            print("❌ Endpoint /api/coach/invite-coachee NO encontrado")
        else:
            print(f"✅ Endpoint responde (código: {api_response.status_code})")
            try:
                result = api_response.json()
                print(f"   Respuesta: {result}")
            except:
                pass
                
    except Exception as e:
        print(f"❌ Error probando endpoint: {e}")
    
    print("\n🎯 DIAGNÓSTICO FINAL:")
    print("="*50)
    
    # Verificar elementos clave
    dashboard_content = dashboard_response.text
    
    issues = []
    successes = []
    
    if 'Invitar Coachee' in dashboard_content:
        successes.append("✅ Botón 'Invitar Coachee' presente")
    else:
        issues.append("❌ Botón 'Invitar Coachee' ausente")
    
    if 'function openInvitationModal()' in dashboard_content:
        successes.append("✅ Función openInvitationModal() definida")
    else:
        issues.append("❌ Función openInvitationModal() no definida")
        
    if 'id="invitationModal"' in dashboard_content:
        successes.append("✅ Modal de invitación presente")
    else:
        issues.append("❌ Modal de invitación ausente")
        
    if 'function showToast(' in dashboard_content:
        successes.append("✅ Función showToast definida")
    else:
        issues.append("❌ Función showToast no definida")
    
    print("ELEMENTOS FUNCIONANDO:")
    for success in successes:
        print(f"  {success}")
    
    if issues:
        print("\nPROBLEMAS ENCONTRADOS:")
        for issue in issues:
            print(f"  {issue}")
    else:
        print("\n🎉 ¡TODOS LOS ELEMENTOS ESTÁN PRESENTES!")
        print("El botón 'Invitar Coachee' debería funcionar correctamente.")
    
    return len(issues) == 0

if __name__ == "__main__":
    test_invitation_with_login()
