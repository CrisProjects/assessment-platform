#!/usr/bin/env python3
"""
Monitor continuo del deployment en Render
"""
import requests
import time
import json
from datetime import datetime

def monitor_render_deployment():
    """Monitor continuo del estado de Render"""
    base_url = "https://assessment-platform-latest.onrender.com"
    
    print("🔍 MONITOR CONTINUO DE RENDER")
    print(f"URL: {base_url}")
    print("Presiona Ctrl+C para detener")
    print("-" * 50)
    
    consecutive_failures = 0
    last_status = None
    
    while True:
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Test root endpoint
            try:
                response = requests.get(f"{base_url}/", timeout=10)
                status = response.status_code
                
                if status == 200:
                    try:
                        data = response.json()
                        if last_status != "SUCCESS":
                            print(f"✅ {timestamp} - ÉXITO! Status: {status}")
                            print(f"   Response: {json.dumps(data, indent=2)}")
                            
                            # Test some API endpoints
                            print("   Probando endpoints API:")
                            for endpoint in ["/api/health", "/api/init-db"]:
                                try:
                                    api_response = requests.get(f"{base_url}{endpoint}", timeout=10)
                                    print(f"     {endpoint}: {api_response.status_code}")
                                except:
                                    print(f"     {endpoint}: ERROR")
                            
                        last_status = "SUCCESS"
                        consecutive_failures = 0
                        
                    except:
                        print(f"⚠️ {timestamp} - Status 200 pero no JSON: {response.text[:100]}")
                        
                elif status == 404:
                    if last_status != "404":
                        print(f"❌ {timestamp} - 404 Not Found")
                    last_status = "404"
                    consecutive_failures += 1
                    
                else:
                    print(f"⚠️ {timestamp} - Status inesperado: {status}")
                    print(f"   Response: {response.text[:100]}")
                    last_status = f"STATUS_{status}"
                    
            except requests.exceptions.RequestException as e:
                if "timeout" in str(e).lower():
                    if last_status != "TIMEOUT":
                        print(f"⏱️ {timestamp} - Timeout")
                    last_status = "TIMEOUT"
                else:
                    if last_status != "CONNECTION_ERROR":
                        print(f"🔌 {timestamp} - Error de conexión: {e}")
                    last_status = "CONNECTION_ERROR"
                consecutive_failures += 1
            
            # Status summary
            if consecutive_failures > 10 and consecutive_failures % 10 == 0:
                print(f"📊 {timestamp} - {consecutive_failures} fallos consecutivos")
            
            time.sleep(5)  # Check every 5 seconds
            
        except KeyboardInterrupt:
            print(f"\n🛑 Monitor detenido por el usuario")
            break
        except Exception as e:
            print(f"❗ Error en monitor: {e}")
            time.sleep(5)

if __name__ == "__main__":
    monitor_render_deployment()
