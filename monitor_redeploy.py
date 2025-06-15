#!/usr/bin/env python3
"""
Script para monitorear el redeploy de Render y verificar cuando esté completo
"""
import requests
import time
import sys

def check_deployment():
    """Verificar el estado del deployment"""
    url = "https://assessment-platform-1nuo.onrender.com/"
    
    try:
        print(f"🔍 Verificando {url}...")
        response = requests.get(url, timeout=10)
        
        print(f"📊 Status Code: {response.status_code}")
        
        # Verificar si es el index.html (debería contener "Plataforma de Evaluación de Asertividad")
        content = response.text.lower()
        
        if "plataforma de evaluación de asertividad" in content and "evaluación de asertividad" in content:
            print("✅ SUCCESS: index.html está siendo servido correctamente!")
            return True
        elif "login" in content and "iniciar sesión" in content:
            print("⚠️  STILL OLD: Aún mostrando página de login")
            return False
        else:
            print("❓ UNKNOWN: Contenido no reconocido")
            print(f"Primeras 200 chars: {response.text[:200]}...")
            return False
            
    except requests.exceptions.Timeout:
        print("⏰ TIMEOUT: El servidor está tardando en responder (posible redeploy)")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR: {e}")
        return False

def monitor_deployment(max_attempts=20, delay=15):
    """Monitorear el deployment durante un tiempo específico"""
    print("🚀 Iniciando monitoreo del redeploy de Render...")
    print(f"   Intentos máximos: {max_attempts}")
    print(f"   Intervalo: {delay} segundos")
    print("=" * 50)
    
    for attempt in range(1, max_attempts + 1):
        print(f"\n[Intento {attempt}/{max_attempts}] {time.strftime('%H:%M:%S')}")
        
        if check_deployment():
            print("\n🎉 REDEPLOY COMPLETADO EXITOSAMENTE!")
            print("   La aplicación está sirviendo el index.html correctamente.")
            return True
        
        if attempt < max_attempts:
            print(f"⏳ Esperando {delay} segundos antes del siguiente intento...")
            time.sleep(delay)
    
    print("\n❌ TIMEOUT: El redeploy no se completó en el tiempo esperado")
    print("   Posibles causas:")
    print("   - El redeploy está tomando más tiempo del esperado")
    print("   - Hay un error en el código que impide el despliegue")
    print("   - Problemas de conectividad")
    return False

if __name__ == "__main__":
    success = monitor_deployment()
    sys.exit(0 if success else 1)
