#!/usr/bin/env python3
"""
Script para verificar el password hash del coach de prueba
"""
import sqlite3
from werkzeug.security import check_password_hash

def verify_coach_password():
    """Verificar password del coach de prueba"""
    try:
        conn = sqlite3.connect('assessments.db')
        cursor = conn.cursor()
        
        # Obtener el coach de prueba
        cursor.execute("SELECT id, username, password_hash, is_active FROM user WHERE username = 'coach_test'")
        coach = cursor.fetchone()
        
        if not coach:
            print("Coach de prueba no encontrado")
            return
        
        coach_id, username, password_hash, is_active = coach
        
        print(f"Coach encontrado:")
        print(f"  ID: {coach_id}")
        print(f"  Username: {username}")
        print(f"  Is Active: {is_active}")
        print(f"  Password Hash: {password_hash[:50]}...")
        
        # Verificar password
        test_password = 'test123'
        is_valid = check_password_hash(password_hash, test_password)
        
        print(f"\nVerificación de contraseña '{test_password}': {'✅ VÁLIDA' if is_valid else '❌ INVÁLIDA'}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error verificando password: {e}")

if __name__ == "__main__":
    verify_coach_password()
