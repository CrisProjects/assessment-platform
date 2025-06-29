#!/usr/bin/env python3
"""
Script para crear coachees de prueba y datos de progreso
"""

import sqlite3
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash

def create_test_coachees_and_data():
    """Crear coachees de prueba y datos de progreso"""
    
    # Conectar a la base de datos
    conn = sqlite3.connect('assessments.db')
    cursor = conn.cursor()
    
    try:
        # Obtener el coach de prueba
        cursor.execute("SELECT id FROM user WHERE role='coach' LIMIT 1")
        coach_result = cursor.fetchone()
        if not coach_result:
            print("❌ No se encontró coach de prueba")
            return
        coach_id = coach_result[0]
        print(f"✅ Coach ID: {coach_id}")
        
        # Crear coachees de prueba
        coachees_data = [
            ("Ana García", "ana.garcia@example.com", "ana.garcia"),
            ("Carlos Ruiz", "carlos.ruiz@example.com", "carlos.ruiz"),
            ("María López", "maria.lopez@example.com", "maria.lopez"),
            ("David Chen", "david.chen@example.com", "david.chen"),
            ("Elena Rodríguez", "elena.rodriguez@example.com", "elena.rodriguez")
        ]
        
        # Limpiar coachees existentes del coach
        cursor.execute("DELETE FROM user WHERE role='coachee' AND coach_id=?", (coach_id,))
        
        created_coachees = []
        
        for full_name, email, username in coachees_data:
            # Crear coachee
            hashed_password = generate_password_hash("password123")
            
            cursor.execute("""
                INSERT INTO user (username, full_name, email, password_hash, role, coach_id, created_at)
                VALUES (?, ?, ?, ?, 'coachee', ?, ?)
            """, (
                username,
                full_name,
                email,
                hashed_password,
                coach_id,
                datetime.now().isoformat()
            ))
            
            coachee_id = cursor.lastrowid
            created_coachees.append((coachee_id, full_name))
            print(f"✅ Creado coachee: {full_name} (ID: {coachee_id})")
        
        # Obtener el assessment ID
        cursor.execute("SELECT id FROM assessment LIMIT 1")
        assessment_result = cursor.fetchone()
        if not assessment_result:
            print("❌ No se encontró assessment")
            return
        assessment_id = assessment_result[0]
        print(f"✅ Assessment ID: {assessment_id}")
        
        # Limpiar resultados existentes del coach
        cursor.execute("DELETE FROM assessment_result WHERE coach_id=?", (coach_id,))
        print("🧹 Limpiados resultados anteriores")
        
        # Crear evaluaciones de progreso para cada coachee
        total_evaluations = 0
        
        for coachee_id, coachee_name in created_coachees:
            print(f"\n📊 Creando datos de progreso para: {coachee_name}")
            
            # Crear entre 4-7 evaluaciones en los últimos 4 meses
            num_assessments = random.randint(4, 7)
            
            # Generar fechas distribuidas en el tiempo
            dates = []
            for i in range(num_assessments):
                days_ago = random.randint(i * 20 + 5, (i + 1) * 25)
                assessment_date = datetime.now() - timedelta(days=days_ago)
                dates.append(assessment_date)
            
            # Ordenar fechas de más antigua a más reciente
            dates.sort()
            
            # Simular progreso realista
            initial_score = random.randint(25, 45)  # Puntuación inicial baja
            
            for i, assessment_date in enumerate(dates):
                # Simular mejora gradual con algo de variabilidad
                progress_factor = (i / (num_assessments - 1)) if num_assessments > 1 else 0
                improvement = progress_factor * random.randint(25, 45)
                variability = random.randint(-8, 12)
                
                final_score = min(95, max(20, initial_score + improvement + variability))
                
                # Insertar resultado
                cursor.execute("""
                    INSERT INTO assessment_result 
                    (user_id, assessment_id, coach_id, score, completed_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    coachee_id,
                    assessment_id,
                    coach_id,
                    round(final_score, 1),
                    assessment_date.isoformat()
                ))
                
                total_evaluations += 1
                print(f"   📈 Evaluación {i+1}: {round(final_score, 1)}% ({assessment_date.strftime('%Y-%m-%d')})")
        
        # Confirmar cambios
        conn.commit()
        print(f"\n🎉 Datos de prueba creados exitosamente!")
        print(f"👥 Coachees creados: {len(created_coachees)}")
        print(f"📋 Total de evaluaciones: {total_evaluations}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_assertivity_level(score):
    """Obtener nivel de asertividad basado en puntuación"""
    if score >= 80:
        return 'Muy Asertivo'
    elif score >= 60:
        return 'Asertivo'
    elif score >= 40:
        return 'Moderadamente Asertivo'
    else:
        return 'Poco Asertivo'

if __name__ == "__main__":
    print("🚀 Creando coachees de prueba y datos de progreso...")
    create_test_coachees_and_data()
