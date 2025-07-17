#!/usr/bin/env python3
"""
Script para crear un usuario coach de prueba con contraseña conocida
"""
import sqlite3
from werkzeug.security import generate_password_hash

def create_test_coach():
    """Crear un coach de prueba"""
    try:
        conn = sqlite3.connect('instance/assessments.db')
        cursor = conn.cursor()
        
        # Verificar si ya existe un coach de prueba
        cursor.execute("SELECT id FROM user WHERE username = 'coach_test'")
        existing = cursor.fetchone()
        
        if existing:
            print("Coach de prueba ya existe. Actualizando contraseña...")
            # Actualizar contraseña
            password_hash = generate_password_hash('test123')
            cursor.execute("""
                UPDATE user 
                SET password_hash = ?, is_active = 1 
                WHERE username = 'coach_test'
            """, (password_hash,))
        else:
            print("Creando nuevo coach de prueba...")
            # Crear nuevo coach
            password_hash = generate_password_hash('test123')
            cursor.execute("""
                INSERT INTO user (username, email, full_name, role, password_hash, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, ('coach_test', 'coach_test@test.com', 'Coach de Prueba', 'coach', password_hash, 1))
        
        conn.commit()
        
        # Verificar la creación/actualización
        cursor.execute("SELECT id, username, email, full_name FROM user WHERE username = 'coach_test'")
        coach = cursor.fetchone()
        
        if coach:
            print(f"✅ Coach de prueba configurado:")
            print(f"   ID: {coach[0]}")
            print(f"   Username: {coach[1]}")
            print(f"   Email: {coach[2]}")
            print(f"   Nombre: {coach[3]}")
            print(f"   Contraseña: test123")
        
        conn.close()
        
    except Exception as e:
        print(f"Error creando coach de prueba: {e}")

if __name__ == "__main__":
    create_test_coach()
