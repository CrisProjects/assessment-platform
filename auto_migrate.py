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
            
            # MIGRACIÓN 2: Crear tabla 'session_record' si no existe
            try:
                existing_tables = inspector.get_table_names()
                if 'session_record' not in existing_tables:
                    logger.info("🔧 Aplicando migración: Crear tabla 'session_record'")
                    conn.execute(text("""
                        CREATE TABLE session_record (
                            id SERIAL PRIMARY KEY,
                            coach_id INTEGER NOT NULL REFERENCES "user"(id),
                            session_number INTEGER NOT NULL,
                            name VARCHAR(200) NOT NULL,
                            objective TEXT,
                            participants TEXT,
                            content TEXT,
                            commitments TEXT,
                            created_at TIMESTAMP DEFAULT NOW(),
                            updated_at TIMESTAMP DEFAULT NOW()
                        );
                    """))
                    conn.execute(text("""
                        CREATE INDEX ix_session_record_coach_id ON session_record (coach_id);
                    """))
                    conn.execute(text("""
                        CREATE INDEX ix_session_record_created_at ON session_record (created_at);
                    """))
                    conn.commit()
                    logger.info("✅ Migración aplicada: tabla 'session_record' creada")
                else:
                    logger.info("✅ Tabla 'session_record' ya existe")
            except Exception as e:
                logger.error(f"❌ Error en migración session_record: {e}")
                pass

            # MIGRACIÓN 3: Crear tabla 'coaching_agreement' si no existe
            try:
                existing_tables = inspector.get_table_names()
                if 'coaching_agreement' not in existing_tables:
                    logger.info("🔧 Aplicando migración: Crear tabla 'coaching_agreement'")
                    conn.execute(text("""
                        CREATE TABLE coaching_agreement (
                            id SERIAL PRIMARY KEY,
                            coach_id INTEGER NOT NULL REFERENCES "user"(id),
                            coachee_id INTEGER REFERENCES "user"(id),
                            status VARCHAR(20) DEFAULT 'borrador',
                            contract_data TEXT,
                            created_at TIMESTAMP DEFAULT NOW(),
                            updated_at TIMESTAMP DEFAULT NOW()
                        );
                    """))
                    conn.execute(text("CREATE INDEX ix_coaching_agreement_coach_id ON coaching_agreement (coach_id);"))
                    conn.execute(text("CREATE INDEX ix_coaching_agreement_status ON coaching_agreement (status);"))
                    conn.commit()
                    logger.info("✅ Migración aplicada: tabla 'coaching_agreement' creada")
                else:
                    logger.info("✅ Tabla 'coaching_agreement' ya existe")
            except Exception as e:
                logger.error(f"❌ Error en migración coaching_agreement: {e}")
                pass

        engine.dispose()
        return True
        
    except Exception as e:
        logger.error(f"❌ Error en auto-migrations: {e}")
        # No fallar la app, solo logear
        return False

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    apply_migrations()
