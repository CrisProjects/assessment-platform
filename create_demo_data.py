#!/usr/bin/env python3
"""
Script para crear datos de ejemplo manualmente
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app_complete import app, db, User, AssessmentResult, Task, TaskProgress
from datetime import datetime, date, timedelta

def create_demo_data():
    with app.app_context():
        try:
            # Obtener el coachee
            coachee_user = User.query.filter_by(email='coachee@assessment.com').first()
            if not coachee_user:
                print("❌ Coachee no encontrado")
                return
            
            print(f"👤 Coachee encontrado: {coachee_user.full_name}")
            
            # Limpiar datos existentes para evitar duplicados
            print("🧹 Limpiando datos existentes...")
            existing_assessments = AssessmentResult.query.filter_by(user_id=coachee_user.id).all()
            for assessment in existing_assessments:
                if assessment.score in [75.5, 82.0]:  # Solo eliminar nuestros datos de demo
                    db.session.delete(assessment)
            
            existing_tasks = Task.query.filter_by(coachee_id=coachee_user.id).all()
            for task in existing_tasks:
                if "Practicar comunicación" in task.title or "Ejercicio de autoconfianza" in task.title:
                    db.session.delete(task)
            
            db.session.flush()
            
            # Crear evaluaciones de ejemplo
            print("📊 Creando evaluaciones de ejemplo...")
            demo_assessments = [
                {
                    'score': 75.5,
                    'total_questions': 10,
                    'result_text': 'Nivel asertivo moderado. Buena base con áreas de mejora en situaciones de conflicto.',
                    'completed_at': datetime.utcnow() - timedelta(days=7),
                    'dimensional_scores': {
                        'comunicacion': 80,
                        'derechos': 70,
                        'opiniones': 75,
                        'conflictos': 65,
                        'autoconfianza': 85
                    }
                },
                {
                    'score': 82.0,
                    'total_questions': 10,
                    'result_text': 'Excelente progreso en asertividad. Mejora notable en manejo de conflictos.',
                    'completed_at': datetime.utcnow() - timedelta(days=3),
                    'dimensional_scores': {
                        'comunicacion': 85,
                        'derechos': 80,
                        'opiniones': 80,
                        'conflictos': 78,
                        'autoconfianza': 87
                    }
                }
            ]
            
            for assessment_data in demo_assessments:
                assessment_result = AssessmentResult(
                    user_id=coachee_user.id,
                    assessment_id=1,  # Assessment de asertividad
                    score=assessment_data['score'],
                    total_questions=assessment_data['total_questions'],
                    result_text=assessment_data['result_text'],
                    completed_at=assessment_data['completed_at'],
                    dimensional_scores=assessment_data['dimensional_scores']
                )
                db.session.add(assessment_result)
            
            print("✅ Evaluaciones de ejemplo creadas")
            
            # Crear tareas de ejemplo
            print("📋 Creando tareas de ejemplo...")
            coach_user = User.query.filter_by(role='platform_admin').first()
            if not coach_user:
                coach_user = User.query.filter(User.role.in_(['coach', 'platform_admin'])).first()
            
            if coach_user:
                print(f"👨‍💼 Coach asignado: {coach_user.full_name}")
                
                demo_tasks = [
                    {
                        'title': 'Practicar comunicación asertiva',
                        'description': 'Durante esta semana, practica expresar tus opiniones de manera clara y respetuosa en al menos 3 situaciones diferentes.',
                        'category': 'comunicacion',
                        'priority': 'high',
                        'due_date': date.today() + timedelta(days=7)
                    },
                    {
                        'title': 'Ejercicio de autoconfianza',
                        'description': 'Identifica 5 fortalezas personales y escribe ejemplos específicos de cómo las has utilizado exitosamente.',
                        'category': 'autoconfianza',
                        'priority': 'medium',
                        'due_date': date.today() + timedelta(days=5)
                    },
                    {
                        'title': 'Manejo de situaciones conflictivas',
                        'description': 'Lee el material sobre técnicas de resolución de conflictos y practica la técnica "DESC" en una situación real.',
                        'category': 'conflictos',
                        'priority': 'medium',
                        'due_date': date.today() + timedelta(days=10)
                    }
                ]
                
                for task_data in demo_tasks:
                    task = Task(
                        coach_id=coach_user.id,
                        coachee_id=coachee_user.id,
                        title=task_data['title'],
                        description=task_data['description'],
                        category=task_data['category'],
                        priority=task_data['priority'],
                        due_date=task_data['due_date'],
                        is_active=True
                    )
                    db.session.add(task)
                
                # Flush para obtener los IDs
                db.session.flush()
                
                # Agregar progreso a algunas tareas
                tasks = Task.query.filter_by(coachee_id=coachee_user.id).all()
                for task in tasks:
                    if task.category in ['comunicacion', 'autoconfianza']:
                        progress = TaskProgress(
                            task_id=task.id,
                            status='in_progress',
                            progress_percentage=30 if task.category == 'comunicacion' else 60,
                            notes='Progreso inicial registrado automáticamente',
                            updated_by=coachee_user.id
                        )
                        db.session.add(progress)
                
                print("✅ Tareas de ejemplo creadas")
            
            # Confirmar cambios
            db.session.commit()
            print("🎉 Datos de ejemplo creados exitosamente!")
            
            # Verificar datos creados
            evaluations_count = AssessmentResult.query.filter_by(user_id=coachee_user.id).count()
            tasks_count = Task.query.filter_by(coachee_id=coachee_user.id).count()
            print(f"📊 Evaluaciones totales: {evaluations_count}")
            print(f"📋 Tareas totales: {tasks_count}")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    create_demo_data()
