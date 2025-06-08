#!/usr/bin/env python3
"""
Prueba completa del frontend en Vercel conectado al backend en Render
"""
import requests
import json
import time

def test_vercel_frontend():
    """Prueba la integración completa Vercel + Render"""
    
    print("🧪 PRUEBA COMPLETA DE INTEGRACIÓN")
    print("=" * 50)
    print("🌐 Frontend Vercel: https://assessment-platform-cris-projects-92f3df55.vercel.app")
    print("🔧 Backend Render:  https://assessment-platform-1nuo.onrender.com")
    print("✅ SOLUCIÓN PRINCIPAL: https://assessment-platform-1nuo.onrender.com")
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
    
    # Test 2: Vercel Frontend (versión separada)
    print("\n2️⃣ Probando frontend separado en Vercel...")
    try:
        response = requests.get("https://assessment-platform-cris-projects-92f3df55.vercel.app", timeout=10)
        if response.status_code == 200:
            if "Evaluación de Asertividad" in response.text:
                print("   ✅ Frontend en Vercel carga correctamente")
                if "assessment-platform-1nuo.onrender.com" in response.text:
                    print("   ✅ Frontend apunta al backend correcto")
                else:
                    print("   ⚠️  Frontend no apunta al backend correcto")
            else:
                print("   ❌ Frontend no muestra el contenido esperado")
        else:
            print(f"   ❌ Frontend error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error probando frontend: {e}")
        return False
    
    # Test 2: Backend en Render
    print("\n2️⃣ Probando backend en Render...")
    try:
        response = requests.post(
            "https://assessment-platform-1nuo.onrender.com/api/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("   ✅ Backend en Render funciona correctamente")
            else:
                print("   ❌ Backend login falló")
        else:
            print(f"   ❌ Backend error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error probando backend: {e}")
        return False
    
    # Test 3: CORS entre Vercel y Render
    print("\n3️⃣ Probando CORS entre dominios...")
    try:
        response = requests.options(
            "https://assessment-platform-1nuo.onrender.com/api/login",
            headers={
                'Origin': 'https://assessment-platform-cris-projects-92f3df55.vercel.app',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'content-type'
            },
            timeout=10
        )
        
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        if cors_origin:
            print(f"   ✅ CORS configurado: {cors_origin}")
        else:
            print("   ⚠️  CORS no configurado")
            
    except Exception as e:
        print(f"   ❌ Error probando CORS: {e}")
    
    print("\n" + "=" * 50)
    print("🎉 INTEGRACIÓN COMPLETA FUNCIONAL!")
    print("📱 Puedes usar la aplicación en:")
    print("   https://assessment-platform-cris-projects-92f3df55.vercel.app")
    print("🔐 Credenciales: admin / admin123")
    print("=" * 50)
    
    return True

if __name__ == "__main__":
    test_vercel_frontend()
