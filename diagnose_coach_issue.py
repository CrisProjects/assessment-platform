#!/usr/bin/env python3
"""
Script para diagnosticar el problema de evaluaciones no visibles en el dashboard del coach
"""
import sqlite3

def diagnose_coach_problem():
    db_path = "instance/assessments.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("🔍 DIAGNÓSTICO: Problema de evaluaciones no visibles en dashboard del coach")
    print("=" * 80)
    
    # Primero verificar las tablas existentes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f"📊 Tablas en la base de datos: {[table[0] for table in tables]}")
    print()
    
    # Verificar estructura de la tabla user
    cursor.execute("PRAGMA table_info(user)")
    user_columns = cursor.fetchall()
    print("📋 Estructura tabla 'user':")
    for col in user_columns:
        print(f"   {col[1]} ({col[2]})")
    print()
    
    # Obtener todos los coaches
    cursor.execute("SELECT id, username, email, full_name FROM user WHERE role = 'coach'")
    coaches = cursor.fetchall()
    print(f"👨‍💼 COACHES encontrados: {len(coaches)}")
    
    for coach in coaches:
        coach_id, username, email, full_name = coach
        print(f"\n🔍 Analizando COACH: {full_name} (ID: {coach_id})")
        
        # Obtener coachees asignados a este coach
        cursor.execute("""
            SELECT id, username, email, full_name, coach_id 
            FROM user 
            WHERE coach_id = ? AND role = 'coachee'
        """, (coach_id,))
        coachees = cursor.fetchall()
        print(f"   📋 Coachees asignados: {len(coachees)}")
        
        for coachee in coachees:
            coachee_id, coachee_username, coachee_email, coachee_full_name, coachee_coach_id = coachee
            print(f"   👤 COACHEE: {coachee_full_name} (ID: {coachee_id}, coach_id: {coachee_coach_id})")
            
            # Buscar evaluaciones del coachee (método actual del código)
            cursor.execute("""
                SELECT ar.id, ar.assessment_id, ar.score, ar.coach_id, ar.completed_at, 
                       ar.user_id, a.title
                FROM assessment_result ar
                LEFT JOIN assessment a ON ar.assessment_id = a.id
                WHERE ar.user_id = ?
                ORDER BY ar.completed_at DESC
            """, (coachee_id,))
            evaluations = cursor.fetchall()
            
            print(f"      📝 EVALUACIONES encontradas: {len(evaluations)}")
            
            if evaluations:
                for eval_data in evaluations:
                    eval_id, assessment_id, score, eval_coach_id, completed_at, eval_user_id, title = eval_data
                    
                    print(f"      ✅ Evaluación ID {eval_id}:")
                    print(f"         - Título: {title or f'Assessment {assessment_id}'}")
                    print(f"         - Score: {score}")
                    print(f"         - user_id en evaluación: {eval_user_id}")
                    print(f"         - coach_id en evaluación: {eval_coach_id}")
                    print(f"         - coach_id del coachee: {coachee_coach_id}")
                    print(f"         - ¿Coinciden coach_ids?: {'✅ SÍ' if eval_coach_id == coach_id else '❌ NO'}")
                    print(f"         - Completada: {completed_at}")
                    print()
            else:
                print(f"      ❌ NO se encontraron evaluaciones para este coachee")
                
                # Verificar si hay evaluaciones con user_id pero diferente coach_id
                cursor.execute("""
                    SELECT ar.id, ar.coach_id, ar.completed_at, a.title
                    FROM assessment_result ar
                    LEFT JOIN assessment a ON ar.assessment_id = a.id
                    WHERE ar.user_id = ?
                """, (coachee_id,))
                all_evaluations = cursor.fetchall()
                
                if all_evaluations:
                    print(f"      🔍 PERO se encontraron evaluaciones con coach_id diferente:")
                    for eval_data in all_evaluations:
                        eval_id, eval_coach_id, completed_at, title = eval_data
                        print(f"         - ID {eval_id}: {title}, coach_id: {eval_coach_id}")
    
    print("\n" + "=" * 80)
    print("🔧 DIAGNÓSTICO COMPLETO")
    
    # Contar evaluaciones totales
    cursor.execute("SELECT COUNT(*) FROM assessment_result")
    total_evaluations = cursor.fetchone()[0]
    print(f"📊 Total evaluaciones en sistema: {total_evaluations}")
    
    # Evaluaciones con coach_id NULL
    cursor.execute("SELECT COUNT(*) FROM assessment_result WHERE coach_id IS NULL")
    null_coach_evaluations = cursor.fetchone()[0]
    print(f"❓ Evaluaciones sin coach_id: {null_coach_evaluations}")
    
    # Evaluaciones con coach_id válido
    cursor.execute("SELECT COUNT(*) FROM assessment_result WHERE coach_id IS NOT NULL")
    valid_coach_evaluations = cursor.fetchone()[0]
    print(f"✅ Evaluaciones con coach_id: {valid_coach_evaluations}")
    
    conn.close()

if __name__ == "__main__":
    diagnose_coach_problem()
