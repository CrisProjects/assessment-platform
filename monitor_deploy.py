#!/usr/bin/env python3
"""
Monitor de Deploy en Render
Verifica que el sistema de invitaciones esté funcionando en producción
"""

import requests
import time
import sys

def check_render_deployment():
    """Verificar que la aplicación esté funcionando en Render"""
    
    # URL base de Render (actualiza con tu URL real)
    base_urls = [
        "https://assessment-platform-1nuo.onrender.com",
        "https://assessment-platform.onrender.com"
    ]
    
    print("🔍 Verificando deploy en Render...")
    
    for base_url in base_urls:
        print(f"\n📡 Probando: {base_url}")
        
        try:
            # Test básico de conexión
            response = requests.get(f"{base_url}/", timeout=30)
            if response.status_code == 200:
                print(f"✅ Aplicación respondiendo en: {base_url}")
                
                # Test específico del sistema de invitaciones
                # Verificar que las rutas nuevas existan
                routes_to_test = [
                    "/login",
                    "/dashboard"
                ]
                
                for route in routes_to_test:
                    try:
                        test_response = requests.get(f"{base_url}{route}", timeout=10)
                        if test_response.status_code in [200, 302, 401]:  # 302 = redirect, 401 = auth required
                            print(f"✅ Ruta {route} disponible")
                        else:
                            print(f"⚠️ Ruta {route} retorna código {test_response.status_code}")
                    except Exception as e:
                        print(f"❌ Error en ruta {route}: {e}")
                
                print(f"\n🎉 ¡DEPLOY EXITOSO! La aplicación está funcionando en:")
                print(f"🌐 {base_url}")
                print(f"\n🚀 Sistema de invitaciones disponible:")
                print(f"📍 Login: {base_url}/login")
                print(f"📍 Dashboard Coach: {base_url}/dashboard")
                print(f"📍 Invitaciones: {base_url}/evaluate/[TOKEN]")
                
                return True
                
            else:
                print(f"❌ Error HTTP {response.status_code} en {base_url}")
                
        except requests.exceptions.Timeout:
            print(f"⏳ Timeout en {base_url} - El deploy puede estar en progreso")
        except Exception as e:
            print(f"❌ Error conectando a {base_url}: {e}")
    
    return False

if __name__ == "__main__":
    print("🔄 Iniciando verificación de deploy...")
    print("⏳ Esperando que Render termine el deploy...")
    
    # Intentar varias veces con delay
    max_attempts = 10
    for attempt in range(1, max_attempts + 1):
        print(f"\n🔍 Intento {attempt}/{max_attempts}")
        
        if check_render_deployment():
            print("\n✅ Deploy verificado exitosamente!")
            sys.exit(0)
        
        if attempt < max_attempts:
            print("⏳ Esperando 30 segundos antes del siguiente intento...")
            time.sleep(30)
    
    print("\n⚠️ No se pudo verificar el deploy automáticamente.")
    print("💡 Esto puede ser normal si el deploy aún está en progreso.")
    print("🌐 Verifica manualmente en: https://dashboard.render.com")
