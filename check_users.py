#!/usr/bin/env python3
"""
Script para verificar usuarios existentes en la base de datos
"""
import sqlite3

def check_database_users():
    """Verificar usuarios en la base de datos"""
    try:
        conn = sqlite3.connect('assessments.db')
        cursor = conn.cursor()
        
        # Verificar tabla de usuarios
        cursor.execute("SELECT id, username, email, full_name, role, is_active FROM user")
        users = cursor.fetchall()
        
        print("=== USUARIOS EN LA BASE DE DATOS ===\n")
        
        if users:
            print(f"Total de usuarios: {len(users)}\n")
            
            for user in users:
                user_id, username, email, full_name, role, is_active = user
                status = "Activo" if is_active else "Inactivo"
                print(f"ID: {user_id}")
                print(f"Username: {username}")
                print(f"Email: {email}")
                print(f"Nombre: {full_name}")
                print(f"Rol: {role}")
                print(f"Estado: {status}")
                print("-" * 40)
        else:
            print("No hay usuarios en la base de datos")
        
        # Verificar coaches específicamente
        cursor.execute("SELECT id, username, email, full_name, is_active FROM user WHERE role = 'coach'")
        coaches = cursor.fetchall()
        
        print(f"\n=== COACHES DISPONIBLES ===")
        print(f"Total de coaches: {len(coaches)}\n")
        
        for coach in coaches:
            coach_id, username, email, full_name, is_active = coach
            status = "Activo" if is_active else "Inactivo"
            print(f"Coach ID: {coach_id} - {username} ({full_name}) - {status}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error verificando base de datos: {e}")

if __name__ == "__main__":
    check_database_users()
