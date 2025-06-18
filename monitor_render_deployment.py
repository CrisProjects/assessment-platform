#!/usr/bin/env python3
"""
Script para monitorear el despliegue en Render y verificar cuando el endpoint /api/force-init-db esté disponible
"""

import requests
import time
import sys
from datetime import datetime

def check_endpoint_availability():
    """Verifica si el endpoint /api/force-init-db está disponible"""
    base_url = "https://assessment-platform-1uot.onrender.com"
    endpoint = "/api/force-init-db"
    
    try:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Verificando {base_url}{endpoint}...")
        response = requests.get(f"{base_url}{endpoint}", timeout=10)
        
        if response.status_code == 404:
            return False, "Endpoint no encontrado (404)"
        else:
            return True, f"Endpoint disponible (Status: {response.status_code})"
            
    except requests.exceptions.RequestException as e:
        return False, f"Error de conexión: {str(e)}"

def check_basic_app():
    """Verifica si la aplicación básica está respondiendo"""
    base_url = "https://assessment-platform-1uot.onrender.com"
    
    try:
        response = requests.get(base_url, timeout=10)
        return response.status_code == 200, f"App status: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"App error: {str(e)}"

def main():
    print("🚀 Monitoreando despliegue en Render...")
    print("=" * 50)
    
    max_attempts = 30  # 30 intentos = ~15 minutos
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        
        # Verificar si la app básica responde
        app_ok, app_msg = check_basic_app()
        print(f"[{attempt:2d}/{max_attempts}] App básica: {app_msg}")
        
        # Verificar si el endpoint específico está disponible
        endpoint_ok, endpoint_msg = check_endpoint_availability()
        print(f"[{attempt:2d}/{max_attempts}] Force-init-db: {endpoint_msg}")
        
        if endpoint_ok:
            print("\n✅ ¡ÉXITO! El endpoint /api/force-init-db está ahora disponible")
            print("🔄 Procediendo a probar la inicialización de la base de datos...")
            return True
            
        if not app_ok:
            print("⚠️  La aplicación principal no responde. Posible redespliegue en curso...")
        
        print("-" * 30)
        time.sleep(30)  # Esperar 30 segundos entre intentos
    
    print("\n❌ Timeout: El endpoint no estuvo disponible después de 15 minutos")
    print("💡 Puede que el despliegue tome más tiempo o haya un problema")
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
