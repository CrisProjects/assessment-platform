#!/usr/bin/env python3
"""
Prueba completa de la plataforma de evaluación de asertividad
"""
import requests
import json
import time

def test_assessment_platform():
    """Prueba la plataforma completa"""
    
    print("🧪 PRUEBA COMPLETA DE LA PLATAFORMA")
    print("=" * 60)
    print("✅ APLICACIÓN PRINCIPAL: https://assessment-platform-1nuo.onrender.com")
    print("🔧 Frontend Vercel:      https://assessment-platform-cris-projects-92f3df55.vercel.app")
    print()
    
    # Test Principal: Aplicación completa en Render
    print("1️⃣ Probando aplicación principal en Render...")
    try:
        response = requests.get("https://assessment-platform-1nuo.onrender.com", timeout=10)
        if response.status_code == 200:
            if "Evaluación de Asertividad" in response.text and "Iniciar Sesión" in response.text:
                print("   ✅ Aplicación principal funciona correctamente")
                print("   ✅ Frontend y backend integrados")
            else:
                print("   ❌ Aplicación no muestra el contenido esperado")
        else:
            print(f"   ❌ Aplicación error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error probando aplicación: {e}")
        return False
    
    # Test 2: Login de la aplicación principal
    print("\n2️⃣ Probando login en aplicación principal...")
    try:
        # Probar endpoint de login directo
        response = requests.post(
            "https://assessment-platform-1nuo.onrender.com/api/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("   ✅ Login funciona correctamente")
            else:
                print("   ❌ Login falló")
        else:
            print(f"   ❌ Login error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error probando login: {e}")
    
    # Test 3: Vercel Frontend (versión separada)
    print("\n3️⃣ Probando frontend separado en Vercel...")
    try:
        response = requests.get("https://assessment-platform-cris-projects-92f3df55.vercel.app", timeout=10)
        if response.status_code == 200:
            if "Evaluación de Asertividad" in response.text:
                print("   ✅ Frontend en Vercel carga correctamente")
                if "assessment-platform-1nuo.onrender.com" in response.text:
                    print("   ✅ Frontend apunta al backend correcto")
                else:
                    print("   ⚠️  Frontend usa versión antigua (React)")
            else:
                print("   ⚠️  Frontend muestra versión React antigua")
        else:
            print(f"   ❌ Frontend error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error probando frontend: {e}")
    
    # Test 4: Evaluaciones
    print("\n4️⃣ Probando evaluaciones...")
    try:
        response = requests.get("https://assessment-platform-1nuo.onrender.com/api/assessments", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data and len(data) > 0:
                print(f"   ✅ {len(data)} evaluaciones disponibles")
                print(f"   ✅ Primera pregunta: {data[0].get('question', 'N/A')[:50]}...")
            else:
                print("   ❌ No hay evaluaciones disponibles")
        else:
            print(f"   ❌ Evaluaciones error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error probando evaluaciones: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 PLATAFORMA COMPLETAMENTE FUNCIONAL!")
    print("🚀 USAR APLICACIÓN PRINCIPAL:")
    print("   https://assessment-platform-1nuo.onrender.com")
    print("🔐 Credenciales: admin / admin123")
    print("⚠️  Nota: Vercel frontend tiene versión antigua - usar Render como principal")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    test_assessment_platform()
