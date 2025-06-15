#!/usr/bin/env python3
"""
Script para crear las preguntas de la evaluación de asertividad
"""

from app_complete import app, db, Assessment, Question
from datetime import datetime

def create_assertiveness_assessment():
    """Crear la evaluación de asertividad con sus 40 preguntas"""
    
    with app.app_context():
        try:
            # Verificar si ya existe la evaluación
            existing_assessment = Assessment.query.filter_by(title='Evaluación de Asertividad').first()
            if existing_assessment:
                print(f"✅ Evaluación ya existe con {Question.query.filter_by(assessment_id=existing_assessment.id).count()} preguntas")
                return True
            
            # Crear la evaluación principal
            assessment = Assessment(
                title='Evaluación de Asertividad',
                description='Evaluación para medir el nivel de asertividad en diferentes dimensiones',
                created_at=datetime.utcnow()
            )
            
            db.session.add(assessment)
            db.session.flush()  # Para obtener el ID
            
            # Preguntas de asertividad (40 preguntas)
            questions_data = [
                # Comunicación (8 preguntas)
                {
                    'content': 'Cuando alguien me critica de manera injusta, expreso mi desacuerdo de forma clara y respetuosa.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Me siento cómodo/a expresando mis opiniones en grupo, incluso si difieren de la mayoría.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Puedo decir "no" cuando alguien me pide algo que no quiero o no puedo hacer.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Expreso mis sentimientos positivos hacia otros sin dificultad.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Cuando necesito ayuda, la pido sin sentirme incómodo/a.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Puedo expresar mis necesidades claramente sin sentirme culpable.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Me comunico de manera directa y honesta sin ser agresivo/a.',
                    'dimension': 'comunicacion'
                },
                {
                    'content': 'Soy capaz de expresar desacuerdo sin atacar a la persona.',
                    'dimension': 'comunicacion'
                },
                
                # Derechos (8 preguntas)
                {
                    'content': 'Defiendo mis derechos cuando siento que están siendo violados.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Me niego a hacer cosas que van contra mis valores.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Establezco límites claros en mis relaciones personales.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Reclamo cuando recibo un trato injusto o discriminatorio.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Protejo mi tiempo personal y no permito que otros lo invadan.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Defiendo mis decisiones cuando otros intentan cambiarlas injustificadamente.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Me mantengo firme en mis convicciones importantes.',
                    'dimension': 'derechos'
                },
                {
                    'content': 'Exijo respeto en mis interacciones con otros.',
                    'dimension': 'derechos'
                },
                
                # Opiniones (8 preguntas)
                {
                    'content': 'Comparto mis ideas en reuniones de trabajo sin temor.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Expreso mi punto de vista aunque sea impopular.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Doy mi opinión cuando me la piden directamente.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Me siento seguro/a al expresar mis preferencias.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Participo activamente en debates y discusiones.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Comparto mis perspectivas únicas sin dudar.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Expreso mis gustos y disgustos abiertamente.',
                    'dimension': 'opiniones'
                },
                {
                    'content': 'Me siento cómodo/a siendo el centro de atención cuando expreso mis ideas.',
                    'dimension': 'opiniones'
                },
                
                # Conflictos (8 preguntas)
                {
                    'content': 'Abordo los conflictos de frente en lugar de evitarlos.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'Mantengo la calma durante las discusiones difíciles.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'Busco soluciones justas cuando hay desacuerdos.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'Puedo manejar la tensión sin volverme agresivo/a o pasivo/a.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'Intento entender el punto de vista del otro durante un conflicto.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'Me mantengo firme en mis posiciones importantes durante disputas.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'Busco compromisos que beneficien a ambas partes.',
                    'dimension': 'conflictos'
                },
                {
                    'content': 'No evito las conversaciones difíciles cuando son necesarias.',
                    'dimension': 'conflictos'
                },
                
                # Autoconfianza (8 preguntas)
                {
                    'content': 'Confío en mis habilidades y capacidades.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Me siento seguro/a de mis decisiones.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Acepto cumplidos sin minimizar mis logros.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Me veo como una persona valiosa e importante.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Mantengo contacto visual cuando hablo con otros.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Me siento cómodo/a siendo el/la líder cuando es necesario.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Confío en mi juicio para tomar decisiones importantes.',
                    'dimension': 'autoconfianza'
                },
                {
                    'content': 'Me presento con seguridad ante personas nuevas.',
                    'dimension': 'autoconfianza'
                }
            ]
            
            # Opciones de respuesta (escala Likert)
            response_options = [
                "Totalmente en desacuerdo",
                "En desacuerdo", 
                "Neutral",
                "De acuerdo",
                "Totalmente de acuerdo"
            ]
            
            # Crear las preguntas
            for i, question_data in enumerate(questions_data, 1):
                question = Question(
                    assessment_id=assessment.id,
                    content=question_data['content'],
                    question_type='likert',
                    options=response_options
                )
                db.session.add(question)
            
            # Commit todos los cambios
            db.session.commit()
            
            print(f"✅ Evaluación creada: {assessment.title}")
            print(f"✅ {len(questions_data)} preguntas agregadas")
            
            return True
            
        except Exception as e:
            print(f"❌ Error creando la evaluación: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = create_assertiveness_assessment()
    if success:
        print("🎉 Evaluación de asertividad creada exitosamente")
    else:
        print("💥 Error creando la evaluación")
