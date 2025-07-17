#!/usr/bin/env python3
"""
Script para probar los endpoints del coach y validar que funcionen correctamente
"""
from app_complete import app, db, User, AssessmentResult
import json

def test_coach_endpoints():
    """Probar endpoints del coach"""
    with app.app_context():
        # Obtener el coach de prueba
        coach = User.query.filter_by(email='coach@test.com', role='coach').first()
        if not coach:
            print("❌ No se encontró coach de prueba")
            return False
        
        print(f"✅ Coach encontrado: {coach.full_name} (ID: {coach.id})")
        
        # Obtener coachees asignados a este coach
        coachees = User.query.filter_by(role='coachee', coach_id=coach.id).all()
        print(f"✅ Coachees asignados: {len(coachees)}")
        
        for coachee in coachees:
            print(f"   - {coachee.full_name} ({coachee.email})")
            
            # Verificar evaluaciones del coachee
            assessments = AssessmentResult.query.filter_by(user_id=coachee.id).all()
            print(f"     📊 Evaluaciones: {len(assessments)}")
            
            if assessments:
                latest = assessments[0]
                print(f"     📈 Última evaluación: {latest.score}% ({latest.completed_at})")
                
                # Verificar datos del result_text
                if latest.result_text:
                    try:
                        data = json.loads(latest.result_text)
                        print(f"     ✅ Datos JSON válidos: {list(data.keys())}")
                        
                        if 'dimensional_scores' in data:
                            print(f"     📊 Puntuaciones dimensionales: {data['dimensional_scores']}")
                        
                        if 'analysis' in data:
                            analysis = data['analysis']
                            print(f"     🎯 Fortalezas: {len(analysis.get('strengths', []))}")
                            print(f"     🎯 Mejoras: {len(analysis.get('improvements', []))}")
                    except json.JSONDecodeError:
                        print(f"     ❌ Error al parsear JSON de evaluación")
                else:
                    print(f"     ⚠️  No hay datos JSON en result_text")
        
        return True

if __name__ == "__main__":
    print("🔍 Probando endpoints del coach...")
    test_coach_endpoints()
