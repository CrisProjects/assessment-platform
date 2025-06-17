#!/usr/bin/env python3
"""
Script para crear datos de prueba en la base de datos de producción
"""

from app_complete import app, db, User, Assessment, Question, AssessmentResult
import json
from datetime import datetime, timedelta
import random

def create_sample_data():
    """Crear assessment y evaluaciones de prueba"""
    try:
        with app.app_context():
            print("🌱 Creando datos de prueba...")
            
            # Verificar si ya hay assessments
            existing_assessment = Assessment.query.filter_by(title="Evaluación de Asertividad").first()
            if existing_assessment:
                print(f"Ya existe assessment: {existing_assessment.title}")
                assessment = existing_assessment
            else:
                # Crear assessment
                admin = User.query.filter_by(username="admin").first()
                if not admin:
                    print("❌ No se encontró usuario admin")
                    return False
                
                assessment = Assessment(
                    title="Evaluación de Asertividad",
                    description="""Esta evaluación ayuda a evaluar tu nivel de asertividad en diversas situaciones. 
                    La asertividad es la habilidad de expresarte efectivamente y defender tu punto de vista mientras 
                    respetas los derechos y creencias de otros.""",
                    creator_id=admin.id
                )
                db.session.add(assessment)
                db.session.flush()
                print(f"✅ Assessment creado: {assessment.title}")
                
                # Crear preguntas
                questions_data = [
                    {
                        "content": "Cuando alguien te critica injustamente, ¿cómo respondes típicamente?",
                        "type": "multiple_choice",
                        "options": [
                            "Permanezco en silencio para evitar conflictos",
                            "Me defiendo calmadamente con hechos",
                            "Me enojo y me pongo a la defensiva",
                            "Trato de cambiar el tema"
                        ]
                    },
                    {
                        "content": "Si un amigo constantemente pide dinero prestado sin devolverlo, ¿abordarías el tema?",
                        "type": "multiple_choice",
                        "options": [
                            "Sí, tendría una conversación honesta al respecto",
                            "No, evitaría mencionarlo",
                            "Dejaría de prestar pero no lo discutiría",
                            "Pondría excusas para no prestar más"
                        ]
                    },
                    {
                        "content": "En discusiones grupales, ¿con qué frecuencia expresas tu opinión aunque difiera de los demás?",
                        "type": "multiple_choice",
                        "options": [
                            "Siempre - hablo sin importar las opiniones de otros",
                            "A menudo - cuando siento fuertemente sobre el tema",
                            "A veces - solo cuando me siento muy seguro",
                            "Rara vez - usualmente estoy de acuerdo con la mayoría"
                        ]
                    },
                    {
                        "content": "Cuando alguien se mete delante de ti en una fila, ¿cuál es tu reacción típica?",
                        "type": "multiple_choice",
                        "options": [
                            "Señalo cortésmente que hay una fila",
                            "No digo nada pero me siento frustrado",
                            "Los confronto agresivamente",
                            "Los dejo pasar y evito la confrontación"
                        ]
                    },
                    {
                        "content": "¿Cómo manejas cuando necesitas decir 'no' a alguien?",
                        "type": "multiple_choice",
                        "options": [
                            "Digo no clara y directamente",
                            "Invento excusas",
                            "Digo sí aunque no quiera",
                            "Evito a la persona o situación"
                        ]
                    }
                ]
                
                for q_data in questions_data:
                    question = Question(
                        content=q_data["content"],
                        question_type=q_data["type"],
                        options=json.dumps(q_data["options"]),
                        assessment_id=assessment.id
                    )
                    db.session.add(question)
                
                print(f"✅ {len(questions_data)} preguntas creadas")
            
            # Crear evaluaciones de prueba para el coachee_demo
            coachee = User.query.filter_by(username="coachee_demo").first()
            if coachee:
                # Crear 3 evaluaciones con diferentes fechas y puntajes
                sample_results = [
                    {
                        "completed_at": datetime.utcnow() - timedelta(days=30),
                        "score": 6.5,
                        "result_text": "Nivel de asertividad: Moderado. Tienes buenas habilidades básicas de asertividad."
                    },
                    {
                        "completed_at": datetime.utcnow() - timedelta(days=15),
                        "score": 7.2,
                        "result_text": "Nivel de asertividad: Bueno. Has mejorado en expresar tus opiniones con confianza."
                    },
                    {
                        "completed_at": datetime.utcnow() - timedelta(days=3),
                        "score": 8.1,
                        "result_text": "Nivel de asertividad: Muy bueno. Muestras gran progreso en comunicación asertiva."
                    }
                ]
                
                # Verificar si ya hay resultados
                existing_results = AssessmentResult.query.filter_by(user_id=coachee.id).count()
                if existing_results == 0:
                    for result_data in sample_results:
                        result = AssessmentResult(
                            user_id=coachee.id,
                            assessment_id=assessment.id,
                            score=result_data["score"],
                            total_questions=len(questions_data) if 'questions_data' in locals() else 5,
                            completed_at=result_data["completed_at"],
                            result_text=result_data["result_text"]
                        )
                        db.session.add(result)
                    
                    print(f"✅ {len(sample_results)} evaluaciones de prueba creadas para {coachee.username}")
                else:
                    print(f"Ya existen {existing_results} evaluaciones para {coachee.username}")
            
            # Crear un segundo coachee para mostrar múltiples coachees
            second_coachee = User.query.filter_by(username="maria_test").first()
            if not second_coachee:
                second_coachee = User(
                    username="maria_test",
                    email="maria@test.com",
                    password_hash="dummy_hash",  # No se usará para login real
                    full_name="María González",
                    role="coachee",
                    coach_id=2,  # Asignar al mismo coach
                    is_active=True,
                    created_at=datetime.utcnow() - timedelta(days=45)
                )
                db.session.add(second_coachee)
                db.session.flush()
                
                # Crear algunas evaluaciones para María
                maria_results = [
                    {
                        "completed_at": datetime.utcnow() - timedelta(days=20),
                        "score": 5.8,
                        "result_text": "Nivel de asertividad: En desarrollo. Necesitas trabajar en expresar tus opiniones."
                    },
                    {
                        "completed_at": datetime.utcnow() - timedelta(days=5),
                        "score": 6.9,
                        "result_text": "Nivel de asertividad: Moderado. Estás progresando bien en tus habilidades."
                    }
                ]
                
                for result_data in maria_results:
                    result = AssessmentResult(
                        user_id=second_coachee.id,
                        assessment_id=assessment.id,
                        score=result_data["score"],
                        total_questions=5,
                        completed_at=result_data["completed_at"],
                        result_text=result_data["result_text"]
                    )
                    db.session.add(result)
                
                print(f"✅ Usuario de prueba creado: {second_coachee.username}")
            
            db.session.commit()
            print("✅ Todos los datos de prueba creados exitosamente!")
            
            # Mostrar resumen
            print("\n📊 Resumen de datos:")
            total_users = User.query.count()
            total_assessments = AssessmentResult.query.count()
            total_questions = Question.query.count()
            
            print(f"  - Usuarios: {total_users}")
            print(f"  - Evaluaciones completadas: {total_assessments}")
            print(f"  - Preguntas: {total_questions}")
            
            return True
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = create_sample_data()
    if success:
        print("\n🎉 ¡Datos de prueba creados exitosamente!")
    else:
        print("\n💥 Error al crear datos de prueba")
