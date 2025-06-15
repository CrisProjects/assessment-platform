#!/usr/bin/env python3
"""
Script para crear un usuario admin manualmente y resolver el problema temporalmente
"""
import requests
import json

def create_admin_user_workaround():
    """Crear un usuario admin usando una solución temporal"""
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    print("🔧 SOLUCIÓN TEMPORAL: Creando usuario admin manual")
    print("=" * 60)
    
    # Paso 1: Crear usuario normal con registro
    print("1. Creando usuario 'admin' como coachee...")
    register_data = {
        "username": "admin",
        "password": "admin123",
        "email": "admin@platform.com",
        "full_name": "Administrador"
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/register",
            json=register_data,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        
        if response.status_code == 201:
            data = response.json()
            user_id = data['user_id']
            print(f"   ✅ Usuario creado con ID: {user_id}")
            
            # Paso 2: Usar SQL directo para cambiar el rol (esto requerirá un endpoint especial)
            print("2. Necesitamos cambiar el rol a platform_admin...")
            print("   📝 Esto requiere una actualización en el backend")
            
            # Por ahora, crear un usuario con nombre diferente
            print("\n3. Creando usuario 'platform_admin' alternativo...")
            register_data_alt = {
                "username": "platform_admin",
                "password": "admin123", 
                "email": "platform_admin@platform.com",
                "full_name": "Platform Administrator"
            }
            
            response2 = requests.post(
                f"{base_url}/api/register",
                json=register_data_alt,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            
            if response2.status_code == 201:
                data2 = response2.json()
                print(f"   ✅ Usuario platform_admin creado con ID: {data2['user_id']}")
                
                print("\n📋 ESTADO ACTUAL:")
                print("   • admin/admin123 - rol: coachee")
                print("   • platform_admin/admin123 - rol: coachee") 
                print("\n⚠️ AMBOS USUARIOS TIENEN ROL COACHEE")
                print("   Necesitamos un endpoint para cambiar roles")
                
                return True
            else:
                print(f"   ❌ Error creando platform_admin: {response2.text}")
        else:
            if "Usuario o email ya registrado" in response.text:
                print("   ⚠️ Usuario 'admin' ya existe")
                return "exists"
            else:
                print(f"   ❌ Error: {response.text}")
            
    except Exception as e:
        print(f"   ❌ Error de conexión: {e}")
    
    return False

if __name__ == "__main__":
    result = create_admin_user_workaround()
    
    if result == "exists":
        print("\n🎯 INSTRUCCIONES PARA EL USUARIO:")
        print("   1. Ir a: https://assessment-platform-1nuo.onrender.com")
        print("   2. Login con: admin / admin123") 
        print("   3. Si muestra 'En construcción', el usuario existe pero no tiene permisos de admin")
        print("   4. Esperar a que se complete el deployment con la corrección")
    elif result:
        print("\n✅ USUARIO CREADO EXITOSAMENTE")
        print("   Sin embargo, tendrá rol 'coachee' hasta que se complete el deployment")
    else:
        print("\n❌ NO SE PUDO CREAR EL USUARIO")
        print("   Verificar conectividad y estado del servidor")
