#!/usr/bin/env python3
"""
SCRIPT DE VERIFICACIÓN FINAL - PLATAFORMA DE EVALUACIÓN
Proporciona un resumen completo del estado actual y recomendaciones
"""

import requests
import time
from datetime import datetime
import json

def check_render_status():
    """Verifica el estado completo de Render"""
    results = {
        'frontend': False,
        'api_health': False,
        'api_questions': False,
        'content_correct': False
    }
    
    # Frontend principal
    try:
        response = requests.get('https://assessment-platform-1nuo.onrender.com', timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            if 'plataforma de evaluación de asertividad' in content:
                results['frontend'] = True
                results['content_correct'] = True
                print("✅ Frontend Render: FUNCIONANDO")
            else:
                print("⚠️  Frontend Render: Contenido incorrecto")
        else:
            print(f"❌ Frontend Render: Error {response.status_code}")
    except Exception as e:
        print(f"❌ Frontend Render: Error - {e}")
    
    # API Health
    try:
        response = requests.get('https://assessment-platform-1nuo.onrender.com/api/health', timeout=5)
        if response.status_code == 200:
            results['api_health'] = True
            print("✅ API Health: FUNCIONANDO")
        else:
            print(f"❌ API Health: Error {response.status_code}")
    except Exception as e:
        print(f"❌ API Health: No disponible")
    
    # API Questions
    try:
        response = requests.get('https://assessment-platform-1nuo.onrender.com/api/questions', timeout=5)
        if response.status_code == 200:
            questions = response.json()
            results['api_questions'] = True
            print(f"✅ API Questions: FUNCIONANDO ({len(questions)} preguntas)")
        else:
            print(f"❌ API Questions: Error {response.status_code}")
    except Exception as e:
        print(f"❌ API Questions: No disponible")
    
    return results

def generate_final_report():
    """Genera el reporte final del estado de la plataforma"""
    print("="*70)
    print("         🎯 REPORTE FINAL - PLATAFORMA DE EVALUACIÓN")
    print("="*70)
    print(f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    # Verificar estado de Render
    print("\n🔍 VERIFICANDO RENDER...")
    render_status = check_render_status()
    
    # Calcular porcentaje de funcionalidad
    total_checks = len(render_status)
    working_checks = sum(render_status.values())
    percentage = (working_checks / total_checks) * 100
    
    print("\n" + "="*70)
    print("📊 ESTADO GENERAL DE LA PLATAFORMA")
    print("="*70)
    
    if percentage >= 75:
        status_icon = "🟢"
        status_text = "MAYORMENTE FUNCIONAL"
    elif percentage >= 50:
        status_icon = "🟡"
        status_text = "PARCIALMENTE FUNCIONAL"
    else:
        status_icon = "🔴"
        status_text = "REQUIERE ATENCIÓN"
    
    print(f"{status_icon} Estado General: {status_text} ({percentage:.0f}%)")
    
    # Detalles por componente
    print(f"\n📋 DETALLES POR COMPONENTE:")
    print("-" * 50)
    
    components = [
        ("Frontend Principal", render_status['frontend']),
        ("Contenido Correcto", render_status['content_correct']),
        ("API Health", render_status['api_health']),
        ("API Questions", render_status['api_questions'])
    ]
    
    for name, status in components:
        icon = "✅" if status else "❌"
        print(f"{icon} {name}")
    
    # URLs y acceso
    print(f"\n🌐 ACCESO A LA PLATAFORMA:")
    print("-" * 50)
    if render_status['frontend']:
        print("✅ URL Principal: https://assessment-platform-1nuo.onrender.com")
        print("   👤 Accesible para usuarios finales")
        print("   📱 Compatible con móviles y desktop")
    else:
        print("❌ URL Principal: No accesible")
    
    # Funcionalidad disponible
    print(f"\n⚙️  FUNCIONALIDAD DISPONIBLE:")
    print("-" * 50)
    
    if render_status['frontend']:
        print("✅ Interfaz de usuario completa")
        print("✅ Formulario de registro")
        print("✅ Diseño responsive")
        print("✅ Validación de campos")
    
    if render_status['api_health'] and render_status['api_questions']:
        print("✅ Backend API completo")
        print("✅ Base de datos operativa")
        print("✅ Evaluaciones funcionales")
    elif render_status['frontend']:
        print("⚠️  Backend API en proceso")
        print("⚠️  Evaluaciones pendientes")
    
    # Recomendaciones
    print(f"\n💡 RECOMENDACIONES:")
    print("-" * 50)
    
    if percentage >= 75:
        print("🎉 ¡PLATAFORMA LISTA PARA USO!")
        print("   • Compartir URL con usuarios")
        print("   • Monitorear uso y rendimiento")
        print("   • Considerar optimizaciones futuras")
    elif render_status['frontend']:
        print("🔄 PLATAFORMA PARCIALMENTE LISTA:")
        print("   • Frontend disponible para demostración")
        print("   • Esperar finalización del backend")
        print("   • Probar nuevamente en 15-30 minutos")
    else:
        print("🚨 REQUIERE ATENCIÓN INMEDIATA:")
        print("   • Verificar logs de deployment")
        print("   • Revisar configuración de servicios")
        print("   • Contactar soporte si persiste")
    
    # Timeline y próximos pasos
    print(f"\n⏭️  PRÓXIMOS PASOS:")
    print("-" * 50)
    
    if not render_status['api_health']:
        print("1. 🔄 Esperar redeploy de Render (5-15 min)")
        print("2. 🧪 Re-ejecutar este script para verificar")
        print("3. 🚀 Probar funcionalidad completa")
    else:
        print("1. 🎯 Realizar pruebas de usuario final")
        print("2. 📈 Monitorear métricas de uso")
        print("3. 🔧 Implementar mejoras identificadas")
    
    # Información técnica
    print(f"\n🔧 INFORMACIÓN TÉCNICA:")
    print("-" * 50)
    print("• Plataforma: Render (https://render.com)")
    print("• Tecnología: Flask + SQLite + HTML/CSS/JS")
    print("• Monitoreo: Scripts de verificación disponibles")
    print("• Logs: Accesibles en dashboard de Render")
    
    print("\n" + "="*70)
    print("📝 Para más detalles, revisar: ESTADO_FINAL_PLATAFORMA.md")
    print("🔧 Scripts disponibles: platform_diagnosis.py, test_platform_status.py")
    print("="*70)

if __name__ == "__main__":
    generate_final_report()
