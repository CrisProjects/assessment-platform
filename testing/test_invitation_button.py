#!/usr/bin/env python3
"""
Script para probar el botón "Invitar Coachee" del dashboard del coach
"""

import requests
import json
import time

def test_invitation_button():
    """Probar el botón de invitación de coachees"""
    base_url = "http://127.0.0.1:5002"
    
    print("🧪 Probando el botón 'Invitar Coachee'...")
    
    # 1. Verificar que el dashboard cargue
    print("\n1️⃣ Verificando que el dashboard cargue...")
    try:
        response = requests.get(f"{base_url}/coach-dashboard")
        if response.status_code == 200:
            print("✅ Dashboard del coach carga correctamente")
            
            # Verificar que el botón esté presente
            if 'Invitar Coachee' in response.text:
                print("✅ Botón 'Invitar Coachee' encontrado en el HTML")
            else:
                print("❌ Botón 'Invitar Coachee' NO encontrado en el HTML")
                
            # Verificar que la función JavaScript esté presente
            if 'openInvitationModal()' in response.text:
                print("✅ Función openInvitationModal() encontrada")
            else:
                print("❌ Función openInvitationModal() NO encontrada")
                
            # Verificar que el modal esté presente
            if 'id="invitationModal"' in response.text:
                print("✅ Modal de invitación encontrado en el HTML")
            else:
                print("❌ Modal de invitación NO encontrado en el HTML")
                
        else:
            print(f"❌ Error al cargar dashboard: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return False
    
    # 2. Verificar que el endpoint de API existe
    print("\n2️⃣ Verificando endpoint de API...")
    try:
        # Hacer una prueba de invitación (debería fallar por autenticación, pero el endpoint debe existir)
        response = requests.post(f"{base_url}/api/coach/invite-coachee", 
                               json={"email": "test@test.com", "full_name": "Test User"})
        
        if response.status_code in [401, 403]:  # No autenticado
            print("✅ Endpoint /api/coach/invite-coachee existe (requiere autenticación)")
        elif response.status_code == 404:
            print("❌ Endpoint /api/coach/invite-coachee NO encontrado")
        else:
            print(f"✅ Endpoint responde (código: {response.status_code})")
            
    except Exception as e:
        print(f"❌ Error probando endpoint: {e}")
    
    print("\n📋 Resumen del test:")
    print("- El dashboard del coach debe cargar sin errores JavaScript")
    print("- El botón 'Invitar Coachee' debe aparecer en la interfaz")
    print("- Al hacer clic debe abrir el modal de invitación")
    print("- El formulario debe enviar datos al endpoint correcto")
    print("- Debe mostrar mensajes de éxito/error apropiados")
    
    return True

if __name__ == "__main__":
    test_invitation_button()
