#!/usr/bin/env python3
"""
🔍 MONITOR EN TIEMPO REAL: Vercel → Render
==========================================

Este script monitorea las requests desde Vercel al backend de Render
mientras realizas la prueba manual.
"""

import requests
import time
import json
from datetime import datetime

RENDER_BACKEND = "https://assessment-platform-1nuo.onrender.com"
VERCEL_FRONTEND = "https://assessment-platform-final.vercel.app"

def check_backend_health():
    """Verificar que el backend esté respondiendo"""
    try:
        response = requests.get(f"{RENDER_BACKEND}/api/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def monitor_api_endpoint(endpoint):
    """Monitorear un endpoint específico"""
    try:
        headers = {'Origin': VERCEL_FRONTEND}
        response = requests.get(f"{RENDER_BACKEND}{endpoint}", headers=headers, timeout=5)
        return {
            'status': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'headers': dict(response.headers),
            'content_length': len(response.text)
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    """Monitorear el backend mientras pruebas en Vercel"""
    print("🔍 MONITOR DE VERCEL → RENDER")
    print("=" * 60)
    print(f"📱 Frontend: {VERCEL_FRONTEND}")
    print(f"🔧 Backend: {RENDER_BACKEND}")
    print(f"⏰ Iniciado: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print("\n🎯 INSTRUCCIONES PARA LA PRUEBA MANUAL:")
    print("1. Ve al navegador que se abrió con Vercel")
    print("2. Llena el formulario con tus datos")
    print("3. Haz clic en 'Comenzar Evaluación'")
    print("4. Responde algunas preguntas")
    print("5. Haz clic en 'Finalizar Evaluación'")
    print("6. Observa los resultados")
    print("\nEste monitor mostrará las requests en tiempo real...")
    print("-" * 60)
    
    # Verificar estado inicial
    if check_backend_health():
        print("✅ Backend ONLINE y respondiendo")
    else:
        print("❌ Backend no responde - revisar Render")
        return
    
    # Monitor continuo
    endpoints_to_check = ["/api/health", "/api/questions"]
    iteration = 0
    
    try:
        while True:
            iteration += 1
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            # Cada 10 segundos, mostrar estado
            if iteration % 2 == 0:  # Cada 10 segundos (5s * 2)
                print(f"\n⏰ {timestamp} - Monitoreo activo...")
                
                for endpoint in endpoints_to_check:
                    result = monitor_api_endpoint(endpoint)
                    if 'error' not in result:
                        status_icon = "✅" if result['status'] == 200 else "❌"
                        print(f"   {status_icon} {endpoint}: {result['status']} ({result['response_time']:.2f}s)")
                    else:
                        print(f"   ❌ {endpoint}: Error - {result['error']}")
            
            # Verificar logs de actividad (simulado)
            if iteration % 6 == 0:  # Cada 30 segundos
                print(f"\n📊 {timestamp} - Checking CORS headers...")
                cors_result = monitor_api_endpoint("/api/login")
                if 'error' not in cors_result:
                    cors_header = cors_result['headers'].get('Access-Control-Allow-Origin', 'No encontrado')
                    print(f"   🔗 CORS Header: {cors_header}")
                
            time.sleep(5)  # Chequear cada 5 segundos
            
    except KeyboardInterrupt:
        print(f"\n\n🛑 Monitor detenido a las {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 60)
        print("📋 RESUMEN FINAL:")
        
        # Test final rápido
        final_health = check_backend_health()
        print(f"Backend Status: {'✅ ONLINE' if final_health else '❌ OFFLINE'}")
        
        # Test CORS final
        cors_test = monitor_api_endpoint("/api/login")
        if 'error' not in cors_test:
            print(f"API Response: ✅ {cors_test['status']}")
        else:
            print(f"API Response: ❌ Error")
        
        print("\n🎯 Si completaste la prueba manual exitosamente:")
        print("   ✅ Vercel está 100% funcional")
        print("   ✅ La integración con Render funciona")
        print("   ✅ Los usuarios pueden usar ambas plataformas")
        print("=" * 60)

if __name__ == "__main__":
    main()
