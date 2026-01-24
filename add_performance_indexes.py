#!/usr/bin/env python3
"""
Script para agregar índices de rendimiento a la base de datos
Mejora la velocidad de queries en producción
"""
from app import app, db
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_indexes():
    """Agregar índices para mejorar rendimiento de queries"""
    
    indexes = [
        # Índices para Users (coachees por coach)
        "CREATE INDEX IF NOT EXISTS idx_users_coach_id ON users(coach_id)",
        "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)",
        "CREATE INDEX IF NOT EXISTS idx_users_coach_role ON users(coach_id, role)",
        
        # Índices para AssessmentResult (evaluaciones por usuario)
        "CREATE INDEX IF NOT EXISTS idx_assessment_result_user_id ON assessment_result(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_assessment_result_completed ON assessment_result(completed_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_assessment_result_score ON assessment_result(user_id, score)",
        
        # Índices para Tasks (tareas por coach y coachee)
        "CREATE INDEX IF NOT EXISTS idx_tasks_coach_id ON tasks(coach_id)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_coachee_id ON tasks(coachee_id)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks(category, is_active)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_coach_active ON tasks(coach_id, is_active)",
        
        # Índices para Content (contenido por coach)
        "CREATE INDEX IF NOT EXISTS idx_content_coach_id ON content(coach_id)",
        "CREATE INDEX IF NOT EXISTS idx_content_active ON content(coach_id, is_active)",
        
        # Índices para CoachingSession (sesiones programadas)
        "CREATE INDEX IF NOT EXISTS idx_coaching_session_coach ON coaching_session(coach_id)",
        "CREATE INDEX IF NOT EXISTS idx_coaching_session_date ON coaching_session(session_date)",
        "CREATE INDEX IF NOT EXISTS idx_coaching_session_status ON coaching_session(coach_id, status, session_date)",
    ]
    
    with app.app_context():
        try:
            for index_sql in indexes:
                try:
                    logger.info(f"Creando índice: {index_sql[:80]}...")
                    db.session.execute(text(index_sql))
                    db.session.commit()
                    logger.info("✅ Índice creado exitosamente")
                except Exception as e:
                    logger.warning(f"⚠️ Error creando índice (puede ya existir): {str(e)}")
                    db.session.rollback()
            
            logger.info("🎉 Todos los índices procesados")
            
        except Exception as e:
            logger.error(f"❌ Error general: {str(e)}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    logger.info("🚀 Iniciando creación de índices de rendimiento...")
    add_indexes()
    logger.info("✅ Proceso completado")
