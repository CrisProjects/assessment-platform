#!/usr/bin/env python3
import os
import sys

# Ensure the script can find the app modules
sys.path.insert(0, '/Users/cristiangaldames/Projects/assessment-platform')

# Use the correct import path for production
from app_root import app, db, User, Assessment, Question
from werkzeug.security import generate_password_hash
import json

def seed_production_database():
    """Seed the production database with the assertiveness assessment"""
    with app.app_context():
        print("🌱 Starting database seeding...")
        
        # Clear existing data if needed
        existing_assessment = Assessment.query.filter_by(title="Evaluación de Asertividad").first()
        if existing_assessment:
            print(f"Found existing assessment: {existing_assessment.title}")
            # Delete questions first
            Question.query.filter_by(assessment_id=existing_assessment.id).delete()
            # Delete the assessment
            db.session.delete(existing_assessment)
            db.session.commit()
            print("Cleared existing assessment data")
        
        # Create admin user if not exists
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin")
            admin.set_password("admin123")
            admin.is_admin = True
            db.session.add(admin)
            db.session.flush()
            print("Created admin user")
        else:
            print(f"Admin user already exists: {admin.username}")

        # Create assertiveness assessment
        assessment = Assessment(
            title="Evaluación de Asertividad",
            description="""Esta evaluación ayuda a evaluar tu nivel de asertividad en diversas situaciones. 
            La asertividad es la habilidad de expresarte efectivamente y defender tu punto de vista mientras 
            respetas los derechos y creencias de otros. La prueba te ayudará a entender tu nivel actual de asertividad 
            y las áreas para mejorar.""",
            creator_id=admin.id
        )
        db.session.add(assessment)
        db.session.flush()
        print(f"Created assessment: {assessment.title}")

        # Questions for the assessment (Spanish versions)
        questions = [
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
            },
            {
                "content": "Cuando recibes un mal servicio en un restaurante, ¿cómo respondes?",
                "type": "multiple_choice",
                "options": [
                    "Expreso mis inquietudes cortésmente al mesero",
                    "No digo nada pero dejo una mala propina",
                    "Me quejo en voz alta y exijo ver al gerente",
                    "Nunca regreso al restaurante"
                ]
            },
            {
                "content": "¿Qué tan cómodo te sientes recibiendo cumplidos?",
                "type": "multiple_choice",
                "options": [
                    "Los acepto graciosamente",
                    "Los deflecto o minimizo",
                    "Me siento muy incómodo",
                    "Los rechazo completamente"
                ]
            },
            {
                "content": "Cuando no estás de acuerdo con la idea de tu jefe en una reunión, ¿qué haces típicamente?",
                "type": "multiple_choice",
                "options": [
                    "Expreso mi desacuerdo respetuosamente con alternativas",
                    "Me quedo callado y acepto",
                    "Argumento fuertemente en contra",
                    "Estoy de acuerdo en la reunión pero me quejo con colegas después"
                ]
            },
            {
                "content": "¿Cómo manejas cuando alguien toma tus pertenencias sin preguntar?",
                "type": "multiple_choice",
                "options": [
                    "Lo discuto directamente con ellos",
                    "Doy pistas sutiles al respecto",
                    "Me enojo visiblemente y los confronto",
                    "No digo nada pero me siento resentido"
                ]
            },
            {
                "content": "Cuando logras algo significativo, ¿cómo lo compartes con otros?",
                "type": "multiple_choice",
                "options": [
                    "Lo comparto confiadamente cuando es apropiado",
                    "Espero a que otros lo noten",
                    "No lo menciono en absoluto",
                    "Hablo constantemente de ello"
                ]
            }
        ]

        # Add questions to the assessment
        for i, q in enumerate(questions):
            question = Question(
                content=q["content"],
                question_type=q["type"],
                options=json.dumps(q["options"]) if "options" in q else None,
                assessment_id=assessment.id
            )
            db.session.add(question)

        db.session.commit()
        print(f"✅ Assessment created successfully with {len(questions)} questions!")
        
        # Verify the data
        print("\n📊 Verification:")
        assessments = Assessment.query.all()
        for a in assessments:
            questions_count = Question.query.filter_by(assessment_id=a.id).count()
            print(f"  - {a.title}: {questions_count} questions")

if __name__ == "__main__":
    seed_production_database()
