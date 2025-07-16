#!/usr/bin/env python3
"""
Script para asignar coachees al coach de prueba
"""
import sqlite3

def assign_coachees_to_test_coach():
    """Asignar coachees existentes al coach de prueba"""
    try:
        conn = sqlite3.connect('instance/assessments.db')
        cursor = conn.cursor()
        
        # Obtener el ID del coach de prueba
        cursor.execute("SELECT id FROM user WHERE username = 'coach_test'")
        coach = cursor.fetchone()
        
        if not coach:
            print("Coach de prueba no encontrado")
            return
        
        coach_id = coach[0]
        print(f"Coach de prueba ID: {coach_id}")
        
        # Obtener algunos coachees para asignar
        cursor.execute("SELECT id, username, full_name FROM user WHERE role = 'coachee' LIMIT 3")
        coachees = cursor.fetchall()
        
        print(f"\nAsignando {len(coachees)} coachees al coach de prueba:")
        
        for coachee in coachees:
            coachee_id, username, full_name = coachee
            
            # Asignar coachee al coach
            cursor.execute("UPDATE user SET coach_id = ? WHERE id = ?", (coach_id, coachee_id))
            print(f"  ✅ {full_name} ({username}) asignado")
        
        # También actualizar las evaluaciones existentes
        cursor.execute("""
            UPDATE assessment_result 
            SET coach_id = ? 
            WHERE user_id IN (SELECT id FROM user WHERE coach_id = ?)
        """, (coach_id, coach_id))
        
        conn.commit()
        
        # Verificar asignaciones
        cursor.execute("""
            SELECT u.id, u.username, u.full_name, 
                   COUNT(ar.id) as evaluations
            FROM user u 
            LEFT JOIN assessment_result ar ON u.id = ar.user_id 
            WHERE u.coach_id = ? 
            GROUP BY u.id
        """, (coach_id,))
        
        assigned_coachees = cursor.fetchall()
        
        print(f"\n=== COACHEES ASIGNADOS AL COACH DE PRUEBA ===")
        for coachee in assigned_coachees:
            coachee_id, username, full_name, evaluations = coachee
            print(f"ID: {coachee_id} - {full_name} ({username}) - {evaluations} evaluaciones")
        
        conn.close()
        
    except Exception as e:
        print(f"Error asignando coachees: {e}")

if __name__ == "__main__":
    assign_coachees_to_test_coach()
