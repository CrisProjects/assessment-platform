#!/usr/bin/env python3
"""
Fix database schema issues for the assessment platform
"""
import sqlite3
import os
from app_complete import app, db, Assessment, Question, User
from werkzeug.security import generate_password_hash

def fix_database():
    """Fix database schema and data issues"""
    print("🔧 Fixing database schema...")
    
    with app.app_context():
        # Drop and recreate all tables to fix schema issues
        db.drop_all()
        db.create_all()
        
        print("✅ Database schema recreated")
        
        # Create admin user
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        
        # Create assessment
        assessment = Assessment(
            title='Evaluación de Asertividad',
            description='Una evaluación completa para medir tu nivel de asertividad en diferentes situaciones.'
        )
        db.session.add(assessment)
        db.session.flush()  # Get the ID
        
        # Create questions
        questions_data = [
            {
                'content': 'Cuando alguien critica tu trabajo de manera injusta, ¿cómo sueles responder?',
                'options': [
                    'Permanezco en silencio para evitar el conflicto',
                    'Me defiendo con calma y hechos',
                    'Me enojo y me pongo a la defensiva',
                    'Intento cambiar de tema'
                ]
            },
            {
                'content': 'Si un amigo te pide dinero repetidamente y no lo devuelve, ¿abordarías este tema?',
                'options': [
                    'No, evitaría mencionarlo',
                    'Sí, tendría una conversación honesta al respecto',
                    'Dejaría de prestar pero no lo hablaría',
                    'Pondría excusas para no prestar más'
                ]
            },
            {
                'content': '¿Con qué frecuencia expresas tu opinión en discusiones grupales?',
                'options': [
                    'Rara vez - Suelo estar de acuerdo con la mayoría',
                    'A menudo - Cuando el tema me importa mucho',
                    'Siempre - Hablo sin importar la opinión de los demás',
                    'A veces - Solo cuando me siento muy seguro'
                ]
            },
            {
                'content': 'Cuando alguien se cuela delante de ti en una fila, ¿qué sueles hacer?',
                'options': [
                    'Dejo que se cuelen y evito el conflicto',
                    'Señalo educadamente que hay una fila',
                    'Los confronto agresivamente',
                    'No digo nada pero me frustro'
                ]
            },
            {
                'content': '¿Cómo manejas las solicitudes que no quieres cumplir?',
                'options': [
                    'Digo que sí aunque no quiera',
                    'Digo que no de forma clara y directa',
                    'Evito a la persona o la situación',
                    'Pongo excusas'
                ]
            },
            {
                'content': 'Si tu comida en un restaurante no está preparada como la pediste, ¿qué harías?',
                'options': [
                    'No digo nada pero dejo poca propina',
                    'Expreso mis inquietudes educadamente al camarero',
                    'Me quejo en voz alta y exijo ver al gerente',
                    'Nunca vuelvo al restaurante'
                ]
            },
            {
                'content': '¿Cómo sueles reaccionar ante los cumplidos?',
                'options': [
                    'Los minimizo o desvío',
                    'Acepto los cumplidos con gratitud',
                    'Me siento muy incómodo',
                    'Los rechazo completamente'
                ]
            },
            {
                'content': 'Durante una reunión de equipo, ¿cómo respondes cuando no estás de acuerdo con una idea propuesta?',
                'options': [
                    'Me quedo callado y acepto',
                    'Expreso mi desacuerdo respetuosamente y propongo alternativas',
                    'Discuto fuertemente en contra',
                    'Estoy de acuerdo en la reunión pero me quejo después'
                ]
            },
            {
                'content': 'Si el comportamiento de un colega te molesta, ¿qué harías?',
                'options': [
                    'No digo nada pero me resiento',
                    'Lo hablo directamente con la persona',
                    'Me enojo visiblemente y confronto',
                    'Doy indirectas sutiles'
                ]
            },
            {
                'content': 'Cuando logras algo importante en el trabajo, ¿cómo lo manejas?',
                'options': [
                    'No lo menciono en absoluto',
                    'Lo comparto con confianza cuando es apropiado',
                    'Hablo de ello constantemente',
                    'Espero que otros lo noten'
                ]
            }
        ]
        
        for i, q_data in enumerate(questions_data, 1):
            question = Question(
                assessment_id=assessment.id,
                content=q_data['content'],
                question_type='multiple_choice',
                options=q_data['options'],
                correct_answer=1  # Default assertive answer (index 1)
            )
            db.session.add(question)
        
        db.session.commit()
        print(f"✅ Created {len(questions_data)} questions")
        print("✅ Database fix completed successfully!")
        
        return True

if __name__ == "__main__":
    fix_database()
