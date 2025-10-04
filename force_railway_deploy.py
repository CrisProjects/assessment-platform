#!/usr/bin/env python3
"""
Script para forzar redeploy en Railway y verificar deployment
"""

import os
import sys
import requests
import json
from datetime import datetime

def check_railway_deployment():
    """Verificar el estado del deployment en Railway"""
    
    print("🚀 RAILWAY DEPLOYMENT CHECK")
    print("=" * 50)
    print(f"🕐 Timestamp: {datetime.now().isoformat()}")
    print()
    
    # URLs típicas de Railway (ajustar según tu deployment)
    possible_urls = [
        "https://assessment-platform-production.up.railway.app",
        "https://assessment-platform.up.railway.app", 
        "https://web-production-XXXX.up.railway.app"  # Reemplazar XXXX con tu ID
    ]
    
    print("🔍 VERIFICANDO ENDPOINTS RAILWAY:")
    print("-" * 40)
    
    for url in possible_urls:
        try:
            print(f"Probando: {url}")
            
            # Verificar endpoint de status
            status_response = requests.get(f"{url}/api/status", timeout=10)
            if status_response.status_code == 200:
                print(f"✅ STATUS OK: {url}")
                status_data = status_response.json()
                print(f"   Versión: {status_data.get('version', 'No especificada')}")
                
                # Verificar endpoint de debug
                try:
                    debug_response = requests.get(f"{url}/api/railway-debug", timeout=15)
                    if debug_response.status_code == 200:
                        print(f"✅ DEBUG OK: Endpoint disponible")
                        debug_data = debug_response.json()
                        
                        # Información clave
                        env_info = debug_data.get('environment', {})
                        db_counts = debug_data.get('database_counts', {})
                        issues = debug_data.get('issues', [])
                        
                        print(f"   🌍 Es Railway: {env_info.get('is_railway', 'Unknown')}")
                        print(f"   🗄️ BD Tipo: {env_info.get('database_type', 'Unknown')}")
                        print(f"   📊 Resultados: {db_counts.get('results', 0)}")
                        print(f"   👥 Usuarios: {db_counts.get('users', 0)}")
                        print(f"   📋 Evaluaciones: {db_counts.get('assessments', 0)}")
                        
                        if issues:
                            print(f"   ⚠️ Problemas detectados:")
                            for issue in issues:
                                print(f"      - {issue}")
                        else:
                            print(f"   ✅ Sin problemas detectados")
                        
                        return url, debug_data
                        
                    else:
                        print(f"❌ DEBUG FAIL: {debug_response.status_code}")
                        
                except Exception as e:
                    print(f"❌ DEBUG ERROR: {str(e)}")
                    
            else:
                print(f"❌ STATUS FAIL: {status_response.status_code}")
                
        except Exception as e:
            print(f"❌ CONNECTION ERROR: {str(e)}")
        
        print()
    
    print("❌ No se pudo conectar a ningún endpoint de Railway")
    return None, None

def force_railway_redeploy():
    """Forzar redeploy creando un archivo temporal"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    deploy_file = f"railway_deploy_{timestamp}.txt"
    
    with open(deploy_file, 'w') as f:
        f.write(f"Forced deploy trigger: {datetime.now().isoformat()}\n")
        f.write("This file forces Railway to redeploy the application\n")
        f.write("Latest commit should include Railway debug endpoint\n")
    
    print(f"📝 Archivo de deploy creado: {deploy_file}")
    
    # Hacer commit y push
    os.system(f"git add {deploy_file}")
    os.system(f'git commit -m "force: trigger Railway redeploy - {timestamp}"')
    os.system("git push origin main")
    
    print("🚀 Push realizado - Railway debería hacer redeploy automáticamente")
    print("⏳ Espera 2-3 minutos para que Railway complete el deployment")
    
    return deploy_file

if __name__ == "__main__":
    print("Verificando deployment actual...")
    url, debug_data = check_railway_deployment()
    
    if not url:
        print("\n🚀 Forzando redeploy...")
        deploy_file = force_railway_redeploy()
        print(f"\nPróximos pasos:")
        print(f"1. Espera 2-3 minutos")
        print(f"2. Verifica tu Railway dashboard")
        print(f"3. Prueba los endpoints nuevamente")
    else:
        print(f"\n✅ Railway funciona en: {url}")
        
        if debug_data:
            results_count = debug_data.get('database_counts', {}).get('results', 0)
            if results_count == 0:
                print("\n⚠️ PROBLEMA IDENTIFICADO: No hay resultados en Railway")
                print("Soluciones posibles:")
                print("1. Los datos están solo en SQLite local")
                print("2. Necesitas migrar datos o crear datos de prueba en Railway")
                print("3. Hay un problema con el guardado de evaluaciones en producción")
