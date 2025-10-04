#!/usr/bin/env python3
"""
Script para añadir evaluaciones de prueba y verificar el progreso
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, AssessmentResult, Assessment
from datetime import datetime, timedelta

def add_test_evaluations():
    """Añadir evaluaciones de prueba para verificar el gráfico de progreso"""
    with app.app_context():
        print("🔍 AÑADIENDO EVALUACIONES DE PRUEBA")
        print("=" * 50)
        
        # Buscar usuario prueba
        user = User.query.filter_by(username='prueba').first()
        if not user:
            print("❌ Usuario 'prueba' no encontrado")
            return
            
        print(f"✅ Usuario encontrado: {user.username} (ID: {user.id})")
        
        # Verificar evaluaciones existentes
        existing_results = AssessmentResult.query.filter_by(user_id=user.id).all()
        print(f"📊 Evaluaciones existentes: {len(existing_results)}")
        
        # Obtener evaluaciones disponibles
        assessments = Assessment.query.all()
        print(f"📋 Evaluaciones disponibles: {len(assessments)}")
        
        # Crear fechas escalonadas para simular progreso temporal
        base_date = datetime.now()
        dates = [
            base_date - timedelta(days=10),  # Hace 10 días
            base_date - timedelta(days=7),   # Hace 7 días  
            base_date - timedelta(days=5),   # Hace 5 días
            base_date - timedelta(days=2),   # Hace 2 días
            base_date                        # Hoy
        ]
        
        # Crear evaluaciones adicionales con diferentes puntajes
        new_evaluations = [
            {"assessment_id": 3, "score": 65.5, "date": dates[0]},  # Inteligencia Emocional
            {"assessment_id": 4, "score": 78.2, "date": dates[1]},  # Liderazgo
            {"assessment_id": 5, "score": 82.8, "date": dates[2]},  # Trabajo en Equipo
            {"assessment_id": 1, "score": 55.0, "date": dates[3]},  # Asertividad (nueva)
            {"assessment_id": 2, "score": 85.5, "date": dates[4]},  # DISC (actualizar)
        ]
        
        try:
            for eval_data in new_evaluations:
                assessment = Assessment.query.get(eval_data["assessment_id"])
                if not assessment:
                    continue
                    
                # Verificar si ya existe
                existing = AssessmentResult.query.filter_by(
                    user_id=user.id, 
                    assessment_id=eval_data["assessment_id"]
                ).first()
                
                if existing:
                    # Actualizar existente
                    existing.score = eval_data["score"]
                    existing.completed_at = eval_data["date"]
                    print(f"🔄 Actualizado: {assessment.title} = {eval_data['score']}")
                else:
                    # Crear nuevo
                    new_result = AssessmentResult(
                        user_id=user.id,
                        assessment_id=eval_data["assessment_id"],
                        score=eval_data["score"],
                        total_score=eval_data["score"],
                        total_questions=20,  # Valor por defecto
                        completed_at=eval_data["date"]
                    )
                    db.session.add(new_result)
                    print(f"➕ Creado: {assessment.title} = {eval_data['score']}")
            
            # Confirmar cambios
            db.session.commit()
            print("\n✅ EVALUACIONES AÑADIDAS EXITOSAMENTE")
            
            # Verificar resultado final
            final_results = AssessmentResult.query.filter_by(user_id=user.id).all()
            print(f"\n📊 Total evaluaciones después: {len(final_results)}")
            
            for result in final_results:
                assessment = Assessment.query.get(result.assessment_id)
                print(f"   📋 {assessment.title}: {result.score} pts (fecha: {result.completed_at})")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    add_test_evaluations()
