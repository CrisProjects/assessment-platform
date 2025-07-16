#!/usr/bin/env python3
"""
Script simple para verificar el contenido del dashboard
después de login manual
"""

import requests

def check_dashboard_content():
    """Verificar contenido del dashboard sin login automático"""
    base_url = "http://127.0.0.1:5002"
    
    print("🔍 Verificando contenido del dashboard del coach...")
    print("⚠️  Asegúrate de estar logueado manualmente en el navegador primero!")
    print()
    
    # Simular verificación directa del archivo HTML
    try:
        with open('templates/coach_dashboard.html', 'r', encoding='utf-8') as f:
            dashboard_content = f.read()
        
        print("📁 Analizando archivo coach_dashboard.html:")
        
        # Verificaciones
        checks = [
            ('Botón Invitar Coachee', 'Invitar Coachee' in dashboard_content),
            ('Función openInvitationModal()', 'function openInvitationModal()' in dashboard_content),
            ('Modal de invitación', 'id="invitationModal"' in dashboard_content),
            ('Función showToast', 'function showToast(' in dashboard_content),
            ('Event listener del formulario', 'invitationForm.addEventListener' in dashboard_content),
            ('Bootstrap Modal', 'bootstrap.Modal' in dashboard_content),
            ('Endpoint API', '/api/coach/invite-coachee' in dashboard_content)
        ]
        
        all_good = True
        for check_name, result in checks:
            status = "✅" if result else "❌"
            print(f"  {status} {check_name}")
            if not result:
                all_good = False
        
        print()
        if all_good:
            print("🎉 ¡TODOS LOS ELEMENTOS ESTÁN PRESENTES!")
            print("El botón 'Invitar Coachee' debería funcionar correctamente.")
        else:
            print("⚠️  Hay elementos faltantes que pueden causar problemas.")
        
        # Verificar estructura específica del botón
        if 'onclick="openInvitationModal()"' in dashboard_content:
            print("✅ El botón tiene el onclick correcto")
        else:
            print("❌ El botón no tiene el onclick correcto")
            
        # Contar funciones JavaScript
        js_functions = [
            'function openInvitationModal()',
            'function sendInvitation()',
            'function showToast(',
            'function loadCoachees()',
            'function displayCoachees()'
        ]
        
        print(f"\n📊 Funciones JavaScript encontradas:")
        for func in js_functions:
            count = dashboard_content.count(func)
            if count > 0:
                print(f"  ✅ {func}: {count} vez(es)")
            else:
                print(f"  ❌ {func}: No encontrada")
        
        return all_good
        
    except FileNotFoundError:
        print("❌ No se pudo encontrar el archivo coach_dashboard.html")
        return False
    except Exception as e:
        print(f"❌ Error leyendo archivo: {e}")
        return False

if __name__ == "__main__":
    check_dashboard_content()
