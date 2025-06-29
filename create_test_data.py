#!/usr/bin/env python3
"""
Script para crear datos de prueba para el gráfico de progreso por coachee
"""

import sqlite3
from datetime import datetime, timedelta
import random

def create_test_progress_data():
    """Crear datos de progreso de evaluaciones para testing"""
    
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
        
        # Obtener coachees del coach
        cursor.execute("SELECT id, full_name FROM user WHERE role='coachee' AND coach_id=?", (coach_id,))
        coachees = cursor.fetchall()
        
        if not coachees:
            print("❌ No se encontraron coachees")
            return
        
        print(f"✅ Encontrados {len(coachees)} coachees")
        
        # Obtener el assessment ID
        cursor.execute("SELECT id FROM assessment LIMIT 1")
        assessment_result = cursor.fetchone()
        if not assessment_result:
            print("❌ No se encontró assessment")
            return
        assessment_id = assessment_result[0]
        print(f"✅ Assessment ID: {assessment_id}")
        
        # Limpiar resultados existentes
        cursor.execute("DELETE FROM assessment_result WHERE coach_id=?", (coach_id,))
        print("🧹 Limpiados resultados anteriores")
        
        # Crear evaluaciones de progreso para cada coachee
        for coachee_id, coachee_name in coachees:
            print(f"\n📊 Creando datos para: {coachee_name}")
            
            # Crear entre 3-6 evaluaciones en los últimos 3 meses
            num_assessments = random.randint(3, 6)
            
            for i in range(num_assessments):
                # Fechas distribuidas en los últimos 3 meses
                days_ago = random.randint(7, 90)
                assessment_date = datetime.now() - timedelta(days=days_ago)
                
                # Simular progreso: puntuación aumenta con el tiempo
                base_score = random.randint(30, 50)  # Puntuación inicial base
                progress_bonus = (90 - days_ago) * 0.3  # Mejora con el tiempo
                final_score = min(95, base_score + progress_bonus + random.randint(-5, 15))
                
                # Insertar resultado
                cursor.execute("""
                    INSERT INTO assessment_result 
                    (user_id, assessment_id, coach_id, score, level, completed_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    coachee_id,
                    assessment_id,
                    coach_id,
                    round(final_score, 1),
                    get_assertivity_level(final_score),
                    assessment_date.isoformat(),
                    assessment_date.isoformat()
                ))
                
                print(f"   📈 Evaluación {i+1}: {round(final_score, 1)}% ({assessment_date.strftime('%Y-%m-%d')})")
        
        # Confirmar cambios
        conn.commit()
        print(f"\n🎉 Datos de prueba creados exitosamente!")
        
        # Mostrar resumen
        cursor.execute("SELECT COUNT(*) FROM assessment_result WHERE coach_id=?", (coach_id,))
        total_results = cursor.fetchone()[0]
        print(f"📋 Total de evaluaciones creadas: {total_results}")
        
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
    print("🚀 Creando datos de prueba para gráfico de progreso...")
    create_test_progress_data()
