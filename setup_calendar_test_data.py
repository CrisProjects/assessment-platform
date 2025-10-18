#!/usr/bin/env python3

"""
Script para crear datos de prueba para el sistema de calendario
Agrega disponibilidad y sesiones de prueba para testing
"""

import sys
import os
from datetime import datetime, date, time, timedelta

# Agregar el directorio raíz al path para importar la app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, CoachAvailability, CoachingSession

def setup_test_calendar_data():
    """Configurar datos de prueba para el calendario"""
    with app.app_context():
        print("🗓️ Configurando datos de prueba para el calendario...")
        
        # Buscar el coach y un coachee de prueba
        coach = User.query.filter_by(role='coach').first()
        coachee = User.query.filter_by(role='coachee').first()
        
        if not coach or not coachee:
            print("❌ No se encontraron usuarios coach o coachee")
            return
        
        print(f"✅ Coach encontrado: {coach.full_name} (ID: {coach.id})")
        print(f"✅ Coachee encontrado: {coachee.full_name} (ID: {coachee.id})")
        
        # 1. Crear disponibilidad del coach (Lunes a Viernes, 9:00-17:00)
        print("\n📅 Creando disponibilidad del coach...")
        
        # Eliminar disponibilidad existente
        CoachAvailability.query.filter_by(coach_id=coach.id).delete()
        
        # Crear disponibilidad de Lunes a Viernes
        for day in range(1, 6):  # 1=Lunes, 5=Viernes
            availability = CoachAvailability(
                coach_id=coach.id,
                day_of_week=day,
                start_time=time(9, 0),  # 9:00 AM
                end_time=time(17, 0),   # 5:00 PM
                is_active=True
            )
            db.session.add(availability)
        
        db.session.commit()
        print("✅ Disponibilidad creada: Lunes a Viernes, 9:00-17:00")
        
        # 2. Crear algunas sesiones de prueba
        print("\n📝 Creando sesiones de prueba...")
        
        # Eliminar sesiones existentes para evitar duplicados
        CoachingSession.query.filter_by(coach_id=coach.id).delete()
        
        # Sesión confirmada para mañana
        tomorrow = date.today() + timedelta(days=1)
        session1 = CoachingSession(
            coach_id=coach.id,
            coachee_id=coachee.id,
            session_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(11, 0),
            status='confirmed',
            title='Sesión de Desarrollo Personal',
            description='Revisión de objetivos trimestrales',
            location='Virtual - Zoom'
        )
        db.session.add(session1)
        
        # Sesión pendiente para la próxima semana
        next_week = date.today() + timedelta(days=7)
        session2 = CoachingSession(
            coach_id=coach.id,
            coachee_id=coachee.id,
            session_date=next_week,
            start_time=time(14, 0),
            end_time=time(15, 0),
            status='pending',
            title='Sesión de Seguimiento',
            description='Evaluación de progreso y nuevos desafíos',
            location='Presencial'
        )
        db.session.add(session2)
        
        # Buscar otro coachee para más variedad
        other_coachee = User.query.filter(
            User.role == 'coachee', 
            User.id != coachee.id,
            User.coach_id == coach.id
        ).first()
        
        if other_coachee:
            # Sesión propuesta con otro coachee
            in_3_days = date.today() + timedelta(days=3)
            session3 = CoachingSession(
                coach_id=coach.id,
                coachee_id=other_coachee.id,
                session_date=in_3_days,
                start_time=time(16, 0),
                end_time=time(17, 0),
                status='proposed',
                title='Primera Sesión de Coaching',
                description='Sesión introductoria y establecimiento de objetivos',
                location='Virtual - Teams',
                proposed_by='coach',
                proposal_message='Te propongo este horario para nuestra primera sesión'
            )
            db.session.add(session3)
            print(f"➕ Sesión adicional con {other_coachee.full_name}")
        
        db.session.commit()
        print("✅ Sesiones de prueba creadas:")
        print(f"   - Sesión confirmada: {tomorrow} 10:00-11:00 con {coachee.full_name}")
        print(f"   - Sesión pendiente: {next_week} 14:00-15:00 con {coachee.full_name}")
        if other_coachee:
            print(f"   - Sesión propuesta: {in_3_days} 16:00-17:00 con {other_coachee.full_name}")
        
        # 3. Mostrar resumen
        print("\n📊 Resumen de datos creados:")
        availability_count = CoachAvailability.query.filter_by(coach_id=coach.id).count()
        sessions_count = CoachingSession.query.filter_by(coach_id=coach.id).count()
        
        print(f"   - Slots de disponibilidad: {availability_count}")
        print(f"   - Sesiones totales: {sessions_count}")
        
        print("\n🎉 ¡Datos de prueba del calendario configurados correctamente!")
        print("Ahora puedes probar:")
        print("1. Dashboard del Coach → Agenda")
        print("2. Dashboard del Coachee → Agendar Coach")

if __name__ == '__main__':
    setup_test_calendar_data()
