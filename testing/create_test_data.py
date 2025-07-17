#!/usr/bin/env python3
from app_complete import app, db, User, AssessmentResult
from werkzeug.security import generate_password_hash
import json
from datetime import datetime

with app.app_context():
    # Crear coach
    coach = User(
        username='coachtest',
        email='coach@test.com',
        full_name='Coach Test',
        role='coach'
    )
    coach.password_hash = generate_password_hash('password123')
    db.session.add(coach)
    db.session.commit()
    
    # Buscar coachee existente
    coachee = User.query.filter_by(role='coachee').first()
    if coachee:
        coachee.coach_id = coach.id
        db.session.commit()
        
        # Crear una evaluación de prueba para el coachee con datos completos
        eval_data = {
            'total_score': 54.0,
            'assertiveness_level': 'Moderadamente Asertivo',
            'dimensional_scores': {
                'direct_communication': 52.0,
                'rights_defense': 48.0,
                'opinion_expression': 58.0,
                'conflict_management': 50.0,
                'self_confidence': 62.0
            },
            'dimension_analysis': {
                'direct_communication': {
                    'score': 52.0,
                    'level': 'Moderado',
                    'interpretation': 'Capacidad moderada para expresar ideas de manera directa'
                },
                'rights_defense': {
                    'score': 48.0,
                    'level': 'Bajo',
                    'interpretation': 'Dificultades para hacer valer sus derechos'
                },
                'opinion_expression': {
                    'score': 58.0,
                    'level': 'Moderado-Alto',
                    'interpretation': 'Buena facilidad para expresar opiniones'
                },
                'conflict_management': {
                    'score': 50.0,
                    'level': 'Moderado',
                    'interpretation': 'Habilidades básicas de manejo de conflictos'
                },
                'self_confidence': {
                    'score': 62.0,
                    'level': 'Alto',
                    'interpretation': 'Buena confianza en sus capacidades'
                }
            },
            'analysis': {
                'strengths': [
                    'Buena expresión de opiniones',
                    'Confianza en sus capacidades',
                    'Comunicación clara en situaciones conocidas'
                ],
                'improvements': [
                    'Fortalecer la defensa de derechos personales',
                    'Mejorar el manejo de situaciones conflictivas',
                    'Desarrollar mayor asertividad en comunicación directa'
                ],
                'general_recommendations': [
                    'Programa de entrenamiento en habilidades asertivas',
                    'Técnicas de comunicación asertiva',
                    'Práctica en situaciones de conflicto controladas'
                ]
            },
            'response_details': [
                {'question_id': 1, 'question_text': '¿Sueles expresar tu opinión cuando no estás de acuerdo?', 'response_value': 3, 'order': 1},
                {'question_id': 2, 'question_text': '¿Te resulta fácil decir no cuando alguien te pide algo que no quieres hacer?', 'response_value': 2, 'order': 2},
                {'question_id': 3, 'question_text': '¿Hablas con seguridad en reuniones o grupos?', 'response_value': 3, 'order': 3},
                {'question_id': 4, 'question_text': '¿Defiendes tus derechos cuando sientes que no te tratan justamente?', 'response_value': 2, 'order': 4},
                {'question_id': 5, 'question_text': '¿Te sientes cómodo/a pidiendo favores o ayuda cuando la necesitas?', 'response_value': 3, 'order': 5}
            ]
        }
        
        assessment = AssessmentResult(
            user_id=coachee.id,
            assessment_id=1,
            score=54.0,
            result_text=json.dumps(eval_data),
            completed_at=datetime.now()
        )
        db.session.add(assessment)
        db.session.commit()
        
        print(f'Coach creado: {coach.email}')
        print(f'Coachee asignado: {coachee.email}')
        print(f'Evaluación creada para el coachee')
    else:
        print('No se encontró coachee')
