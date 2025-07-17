#!/usr/bin/env python3
"""
Validación final de funcionalidades core de la aplicación
"""
import requests

def quick_validation():
    """Validación rápida de funcionalidades core"""
    base_url = "http://127.0.0.1:10000"
    session = requests.Session()
    
    print("🚀 VALIDACIÓN FINAL DE FUNCIONALIDADES CORE")
    print("=" * 50)
    
    tests = [
        ("/", "Página principal"),
        ("/dashboard-selection", "Selección de dashboard"),
        ("/admin-login", "Login de admin"),
        ("/coach-login", "Login de coach"),
        ("/coachee-dashboard", "Dashboard de coachee"),
        ("/coach-dashboard", "Dashboard de coach"),
        ("/api/status", "API Status"),
        ("/api/questions", "API Preguntas")
    ]
    
    passed = 0
    for route, name in tests:
        try:
            response = session.get(f"{base_url}{route}")
            if response.status_code in [200, 302]:  # 200 OK o 302 Redirect
                print(f"✅ {name}: OK ({response.status_code})")
                passed += 1
            else:
                print(f"❌ {name}: ERROR ({response.status_code})")
        except Exception as e:
            print(f"❌ {name}: EXCEPCIÓN ({str(e)})")
    
    print("=" * 50)
    print(f"RESULTADO: {passed}/{len(tests)} funcionalidades core funcionando")
    
    if passed == len(tests):
        print("🎉 ¡PERFECTO! Todas las funcionalidades core están funcionando.")
    elif passed >= len(tests) - 1:
        print("👍 Excelente! Casi todas las funcionalidades funcionan correctamente.")
    else:
        print("⚠️ Hay algunas funcionalidades que necesitan atención.")

if __name__ == "__main__":
    quick_validation()
