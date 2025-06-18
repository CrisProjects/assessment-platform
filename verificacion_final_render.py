#!/usr/bin/env python3
"""
Verificación final del estado de Render - Resumen ejecutivo
"""
import requests
import json
from datetime import datetime

def final_render_check():
    """Verificación final y completa del estado de Render"""
    print("🔍 VERIFICACIÓN FINAL - RENDER CRISIS")
    print("=" * 50)
    
    base_url = "https://assessment-platform-latest.onrender.com"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"Timestamp: {timestamp}")
    print(f"URL: {base_url}")
    print()
    
    # 1. Test básico con headers completos
    print("1. 🌐 TEST DE CONECTIVIDAD")
    try:
        response = requests.get(f"{base_url}/", timeout=15)
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers relevantes:")
        
        relevant_headers = ['x-render-routing', 'server', 'content-type', 'date']
        for header in relevant_headers:
            if header in response.headers:
                print(f"     {header}: {response.headers[header]}")
        
        if response.status_code == 200:
            print("   ✅ ÉXITO - Servidor respondiendo")
            try:
                data = response.json()
                print(f"   Response: {json.dumps(data, indent=4)}")
            except:
                print(f"   Response text: {response.text}")
        else:
            print(f"   ❌ FALLO - Status {response.status_code}")
            
    except Exception as e:
        print(f"   🔌 ERROR DE CONEXIÓN: {e}")
    
    print()
    
    # 2. Test de endpoints específicos
    print("2. 🎯 TEST DE ENDPOINTS ESPECÍFICOS")
    
    endpoints = [
        "/health",
        "/api/test", 
        "/api/init-db",
        "/test"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=10)
            status_icon = "✅" if response.status_code == 200 else "❌"
            print(f"   {status_icon} {endpoint}: {response.status_code}")
        except:
            print(f"   🔌 {endpoint}: CONNECTION_ERROR")
    
    print()
    
    # 3. Análisis de infraestructura
    print("3. 🏗️ ANÁLISIS DE INFRAESTRUCTURA")
    
    try:
        # Test de DNS
        import socket
        ip = socket.gethostbyname("assessment-platform-latest.onrender.com")
        print(f"   DNS Resolution: {ip}")
        
        # Test de puerto
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, 443))
        sock.close()
        
        if result == 0:
            print("   Puerto 443: ✅ Abierto")
        else:
            print("   Puerto 443: ❌ Cerrado")
            
    except Exception as e:
        print(f"   Error en análisis de red: {e}")
    
    print()
    
    # 4. Conclusión
    print("4. 📋 CONCLUSIÓN")
    
    try:
        response = requests.head(f"{base_url}/", timeout=10)
        if 'x-render-routing' in response.headers:
            routing_value = response.headers['x-render-routing']
            if routing_value == 'no-server':
                print("   🚨 CONFIRMADO: x-render-routing: no-server")
                print("   📋 DIAGNÓSTICO: Render no tiene ningún servidor ejecutándose")
                print("   🔧 ACCIÓN REQUERIDA: Verificar dashboard de Render y logs de deploy")
            else:
                print(f"   ℹ️ x-render-routing: {routing_value}")
        else:
            print("   ⚠️ No se encontró header x-render-routing")
    except:
        print("   🔌 No se pudo obtener información de routing")
    
    print()
    print("🎯 PRÓXIMOS PASOS RECOMENDADOS:")
    print("   1. Acceder al dashboard de Render")
    print("   2. Revisar logs de build y runtime")  
    print("   3. Verificar estado del servicio")
    print("   4. Considerar recrear el servicio si está corrupto")
    print()
    print("📄 Ver INFORME_FINAL_RENDER_CRISIS.md para análisis completo")

if __name__ == "__main__":
    final_render_check()
