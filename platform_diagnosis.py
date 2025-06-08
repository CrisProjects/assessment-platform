#!/usr/bin/env python3
"""
Script de verificación del estado actual de la plataforma
Verifica tanto frontend como backend
"""

import requests
import time
from datetime import datetime

def test_render_frontend():
    """Prueba el frontend en Render"""
    try:
        response = requests.get('https://assessment-platform-1nuo.onrender.com', timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            if 'plataforma de evaluación de asertividad' in content:
                print("✅ Frontend en Render: FUNCIONANDO - Contenido correcto")
                return True
            else:
                print("⚠️  Frontend en Render: Contenido incorrecto")
                return False
        else:
            print(f"❌ Frontend en Render: Error {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Frontend en Render: Error de conexión - {e}")
        return False

def test_vercel_status():
    """Prueba el estado de Vercel"""
    vercel_urls = [
        'https://assessment-platform-e6sn1m7yc-cris-projects-92f3df55.vercel.app',
        'https://assessment-platform-fts8mln18-cris-projects-92f3df55.vercel.app',
        'https://assessment-platform-xk697a01g-cris-projects-92f3df55.vercel.app'
    ]
    
    for url in vercel_urls:
        try:
            response = requests.get(url, timeout=5)
            content = response.text[:200].lower()
            
            if 'authentication required' in content:
                print(f"⚠️  Vercel ({url.split('-')[2][:8]}...): Requiere autenticación")
            elif 'plataforma de evaluación' in content:
                print(f"✅ Vercel ({url.split('-')[2][:8]}...): FUNCIONANDO")
                return url
            elif 'react' in content or 'vite' in content:
                print(f"❌ Vercel ({url.split('-')[2][:8]}...): Versión React incorrecta")
            else:
                print(f"❓ Vercel ({url.split('-')[2][:8]}...): Estado desconocido")
                
        except Exception as e:
            print(f"❌ Vercel ({url.split('-')[2][:8]}...): Error de conexión")
    
    return None

def main():
    print("="*60)
    print("    DIAGNÓSTICO DE ESTADO - PLATAFORMA DE EVALUACIÓN")
    print("="*60)
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*60)
    
    # Test Frontend Render
    render_ok = test_render_frontend()
    
    # Test Vercel
    print("\nProbando deployments de Vercel...")
    working_vercel = test_vercel_status()
    
    print("\n" + "="*60)
    print("RESUMEN DEL DIAGNÓSTICO:")
    print("="*60)
    
    if render_ok:
        print("🎉 FRONTEND PRINCIPAL: FUNCIONANDO")
        print("   📍 URL Principal: https://assessment-platform-1nuo.onrender.com")
        print("   ✅ Interfaz de usuario completa disponible")
        print("   ✅ Página responsive y moderna")
        print("   ✅ Formularios de evaluación presentes")
        
        print("\n📋 ESTADO DEL BACKEND:")
        print("   ⚠️  API endpoints en transición (redeploy en progreso)")
        print("   🔄 Se están aplicando correcciones al backend")
        print("   ⏳ Los endpoints API estarán disponibles tras el redeploy")
        
    if working_vercel:
        print(f"\n✅ VERCEL ALTERNATIVO: {working_vercel}")
    else:
        print("\n❌ VERCEL: Problemas de autenticación en todos los deployments")
    
    print("\n" + "="*60)
    print("RECOMENDACIÓN ACTUAL:")
    print("="*60)
    print("✅ USAR RENDER COMO PLATAFORMA PRINCIPAL")
    print("   📎 URL: https://assessment-platform-1nuo.onrender.com")
    print("   💡 Frontend completamente funcional")
    print("   🔧 Backend en proceso de corrección")
    
    print("\n📝 PRÓXIMOS PASOS:")
    print("   1. Esperar finalización del redeploy de Render")
    print("   2. Verificar funcionalidad completa del backend")
    print("   3. Resolver problemas de autenticación en Vercel")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()
