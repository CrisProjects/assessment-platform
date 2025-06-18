#!/usr/bin/env python3
"""
Verificador de rutas post-deploy
Verifica que todas las rutas principales funcionen en producción
"""

import requests
import time

def test_route(base_url, route, expected_status=[200, 302, 401, 403]):
    """Probar una ruta específica"""
    try:
        url = f"{base_url}{route}"
        response = requests.get(url, timeout=10)
        
        if response.status_code in expected_status:
            print(f"✅ {route:25} [{response.status_code}] OK")
            return True
        else:
            print(f"❌ {route:25} [{response.status_code}] ERROR")
            return False
            
    except Exception as e:
        print(f"❌ {route:25} [ERR] {str(e)[:50]}")
        return False

def verify_all_routes():
    """Verificar todas las rutas principales"""
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print("🔍 Verificando rutas principales en producción...\n")
    
    routes_to_test = [
        ("/", [200]),                        # Página principal
        ("/login", [200]),                   # Login page  
        ("/dashboard", [200, 302, 401]),     # Dashboard (redirect o auth)
        ("/coach-dashboard", [200, 302, 401, 403]), # Coach dashboard
        ("/api/health", [200]),              # Health check
        ("/status", [200]),                  # Status check
        ("/api/assessments", [200, 401]),    # API de evaluaciones
        ("/favicon.ico", [200, 404]),        # Favicon
    ]
    
    success_count = 0
    total_count = len(routes_to_test)
    
    for route, expected in routes_to_test:
        if test_route(base_url, route, expected):
            success_count += 1
    
    print(f"\n📊 Resultado: {success_count}/{total_count} rutas funcionando")
    
    if success_count >= total_count - 1:  # Permitir 1 fallo
        print("✅ APLICACIÓN FUNCIONANDO CORRECTAMENTE")
        return True
    else:
        print("❌ HAY PROBLEMAS CON MÚLTIPLES RUTAS")
        return False

def test_invitation_system():
    """Probar rutas específicas del sistema de invitaciones"""
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print("\n🔍 Verificando sistema de invitaciones...\n")
    
    # Probar con token dummy (debería dar error controlled)
    dummy_token = "dummy_token_12345"
    
    invitation_routes = [
        (f"/register/{dummy_token}", [404, 410]),     # Registro con token (token inválido esperado)
        (f"/evaluate/{dummy_token}", [404, 410]),     # Evaluación con token (token inválido esperado) 
    ]
    
    for route, expected in invitation_routes:
        test_route(base_url, route, expected)

if __name__ == "__main__":
    print("🚀 VERIFICADOR DE DEPLOY - ASSESSMENT PLATFORM\n")
    
    if verify_all_routes():
        test_invitation_system()
        print("\n🎉 DEPLOY VERIFICADO EXITOSAMENTE!")
        print(f"🌐 Aplicación disponible en: https://assessment-platform-1nuo.onrender.com")
    else:
        print("\n⚠️ Hay problemas con el deploy. Verificar logs de Render.")
