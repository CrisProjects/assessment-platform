#!/usr/bin/env python3
"""
Auto-migration runner - Se ejecuta al iniciar la app
Aplica migraciones pendientes automáticamente
"""
import os
import sys
from sqlalchemy import create_engine, text, inspect
import logging

logger = logging.getLogger(__name__)

def apply_migrations():
    """Aplicar todas las migraciones pendientes"""
    
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        logger.warning("DATABASE_URL no configurada, saltando migraciones")
        return True
    
    # Workaround para Railway/Heroku
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    try:
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            inspector = inspect(engine)
            
            # MIGRACIÓN 1: Agregar columna 'type' a tabla 'task' si no existe
            try:
                columns = [col['name'] for col in inspector.get_columns('task')]
                
                if 'type' not in columns:
                    logger.info("🔧 Aplicando migración: Agregar columna 'type' a tabla 'task'")
                    conn.execute(text("""
                        ALTER TABLE task 
                        ADD COLUMN type VARCHAR(20) DEFAULT 'accion';
                    """))
                    conn.commit()
                    logger.info("✅ Migración aplicada: columna 'type' agregada")
                else:
                    logger.info("✅ Columna 'type' ya existe en tabla 'task'")
            except Exception as e:
                logger.error(f"❌ Error en migración task.type: {e}")
                # No fallar la app por esto
                pass
            
            # Aquí puedes agregar más migraciones en el futuro
            
        engine.dispose()
        return True
        
    except Exception as e:
        logger.error(f"❌ Error en auto-migrations: {e}")
        # No fallar la app, solo logear
        return False

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    apply_migrations()
