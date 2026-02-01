#!/usr/bin/env python3
"""
Script de auto-migración para gamificación
Ejecuta este script UNA VEZ en producción para crear las tablas
"""

import sys
sys.path.insert(0, '.')
from app import app, db
from sqlalchemy import text

SQL_MIGRATION = """
-- Tabla 1: Puntos y nivel de cada coachee
CREATE TABLE IF NOT EXISTS coachee_points (
    id SERIAL PRIMARY KEY,
    coachee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    total_points INTEGER DEFAULT 0,
    current_level INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (coachee_id)
);

-- Tabla 2: Configuración de puntos por tarea
CREATE TABLE IF NOT EXISTS task_points_config (
    id SERIAL PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    difficulty_level VARCHAR(20) DEFAULT 'MEDIA',
    base_points INTEGER NOT NULL DEFAULT 50,
    bonus_multiplier DECIMAL(3,2) DEFAULT 1.0,
    category_bonus INTEGER DEFAULT 0,
    is_repeatable BOOLEAN DEFAULT FALSE,
    max_repetitions INTEGER DEFAULT 1,
    created_by_coach_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (task_id)
);

-- Tabla 3: Historial de transacciones de puntos
CREATE TABLE IF NOT EXISTS point_transactions (
    id SERIAL PRIMARY KEY,
    coachee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    points_earned INTEGER NOT NULL,
    transaction_type VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_point_trans_coachee ON point_transactions(coachee_id, created_at);

-- Tabla 4: Sistema de niveles
CREATE TABLE IF NOT EXISTS levels_system (
    id SERIAL PRIMARY KEY,
    level_number INTEGER UNIQUE NOT NULL,
    level_name VARCHAR(100) NOT NULL,
    points_required INTEGER NOT NULL,
    icon_class VARCHAR(100),
    color_hex VARCHAR(7),
    description TEXT,
    unlock_message TEXT
);

-- Inicializar puntos para coachees existentes
INSERT INTO coachee_points (coachee_id, total_points, current_level)
SELECT id, 0, 1 FROM users WHERE role = 'coachee'
ON CONFLICT (coachee_id) DO NOTHING;
"""

LEVELS_DATA = [
    (1, 'Novato', 0, 'fa-seedling', '#10b981', 'Inicio del viaje', '¡Bienvenido al camino del crecimiento!'),
    (2, 'Aprendiz', 100, 'fa-book', '#3b82f6', 'Primeros pasos', 'Estás aprendiendo y avanzando'),
    (3, 'Explorador', 250, 'fa-compass', '#8b5cf6', 'Descubriendo nuevos horizontes', '¡Sigues explorando!'),
    (4, 'Practicante', 600, 'fa-running', '#f59e0b', 'Práctica constante', 'La constancia es tu fortaleza'),
    (5, 'Competente', 1000, 'fa-medal', '#ec4899', 'Dominio creciente', '¡Tu dedicación da frutos!'),
    (6, 'Experto', 2000, 'fa-crown', '#ef4444', 'Maestría en desarrollo', 'Eres ejemplo de superación'),
    (7, 'Maestro', 5000, 'fa-gem', '#7c3aed', 'Nivel máximo alcanzado', '¡Eres un verdadero maestro!')
]

def run_migration():
    """Ejecuta la migración de gamificación"""
    with app.app_context():
        try:
            print('\n' + '=' * 70)
            print('🚀 INICIANDO MIGRACIÓN DE GAMIFICACIÓN')
            print('=' * 70 + '\n')
            
            # Ejecutar SQL
            print('📝 Creando tablas...')
            db.session.execute(text(SQL_MIGRATION))
            db.session.commit()
            print('✅ Tablas creadas correctamente\n')
            
            # Insertar niveles
            print('📝 Insertando niveles del sistema...')
            for level_data in LEVELS_DATA:
                try:
                    db.session.execute(
                        text("""
                            INSERT INTO levels_system 
                            (level_number, level_name, points_required, icon_class, color_hex, description, unlock_message)
                            VALUES (:num, :name, :points, :icon, :color, :desc, :msg)
                            ON CONFLICT (level_number) DO NOTHING
                        """),
                        {
                            'num': level_data[0],
                            'name': level_data[1],
                            'points': level_data[2],
                            'icon': level_data[3],
                            'color': level_data[4],
                            'desc': level_data[5],
                            'msg': level_data[6]
                        }
                    )
                    print(f'   ✅ Nivel {level_data[0]}: {level_data[1]}')
                except Exception as e:
                    print(f'   ⚠️  Nivel {level_data[0]}: {str(e)[:50]}')
            
            db.session.commit()
            print('\n✅ Niveles insertados correctamente\n')
            
            # Verificar
            levels_count = db.session.execute(text('SELECT COUNT(*) FROM levels_system')).scalar()
            coachees_count = db.session.execute(text('SELECT COUNT(*) FROM coachee_points')).scalar()
            
            print('=' * 70)
            print('✅ MIGRACIÓN COMPLETADA EXITOSAMENTE')
            print('=' * 70)
            print(f'\n📊 Niveles creados: {levels_count}')
            print(f'📊 Coachees inicializados: {coachees_count}\n')
            
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f'\n❌ ERROR EN MIGRACIÓN: {e}\n')
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    print('\n⚠️  ADVERTENCIA: Este script modificará la base de datos')
    print('   Solo ejecutar en producción si las tablas NO existen\n')
    
    response = input('¿Continuar con la migración? (si/no): ')
    
    if response.lower() in ['si', 's', 'yes', 'y']:
        success = run_migration()
        sys.exit(0 if success else 1)
    else:
        print('\n❌ Migración cancelada\n')
        sys.exit(1)
