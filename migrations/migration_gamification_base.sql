-- ============================================
-- MIGRACIÓN: Sistema de Gamificación - Base
-- Fecha: 2026-01-31
-- Descripción: Tablas base para puntos, niveles y logros
-- ============================================

-- Tabla 1: Puntos y nivel de cada coachee
CREATE TABLE IF NOT EXISTS coachee_points (
    id INT PRIMARY KEY AUTO_INCREMENT,
    coachee_id INT NOT NULL,
    total_points INT DEFAULT 0,
    current_level INT DEFAULT 1,
    points_in_level INT DEFAULT 0,
    points_to_next_level INT DEFAULT 100,
    lifetime_points INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (coachee_id) REFERENCES coachees(id) ON DELETE CASCADE,
    UNIQUE KEY unique_coachee (coachee_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla 2: Configuración de puntos por tarea
CREATE TABLE IF NOT EXISTS task_points_config (
    id INT PRIMARY KEY AUTO_INCREMENT,
    task_id INT NOT NULL,
    difficulty_level ENUM('facil', 'media', 'dificil') DEFAULT 'media',
    base_points INT NOT NULL DEFAULT 25,
    bonus_multiplier DECIMAL(3,2) DEFAULT 1.0,
    category_bonus INT DEFAULT 0,
    is_repeatable BOOLEAN DEFAULT FALSE,
    max_repetitions INT DEFAULT 1,
    created_by_coach_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_coach_id) REFERENCES coaches(id),
    UNIQUE KEY unique_task_config (task_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla 3: Historial de transacciones de puntos
CREATE TABLE IF NOT EXISTS point_transactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    coachee_id INT NOT NULL,
    task_id INT,
    achievement_id INT,
    points_earned INT NOT NULL,
    transaction_type ENUM('task_completed', 'achievement_unlocked', 'bonus', 'penalty', 'manual') NOT NULL,
    description TEXT,
    multiplier DECIMAL(3,2) DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (coachee_id) REFERENCES coachees(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL,
    INDEX idx_coachee_date (coachee_id, created_at),
    INDEX idx_transaction_type (transaction_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla 4: Sistema de niveles
CREATE TABLE IF NOT EXISTS levels_system (
    id INT PRIMARY KEY AUTO_INCREMENT,
    level_number INT UNIQUE NOT NULL,
    level_name VARCHAR(100) NOT NULL,
    points_required INT NOT NULL,
    icon_class VARCHAR(100),
    color_hex VARCHAR(7),
    description TEXT,
    unlock_message TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insertar niveles iniciales
INSERT INTO levels_system (level_number, level_name, points_required, icon_class, color_hex, description, unlock_message) VALUES
(1, 'Novato', 0, 'fa-seedling', '#10b981', 'Inicio del viaje', '¡Bienvenido al camino del crecimiento!'),
(2, 'Aprendiz', 100, 'fa-book-reader', '#3b82f6', 'Primeros pasos', 'Estás aprendiendo y avanzando'),
(3, 'Explorador', 250, 'fa-compass', '#8b5cf6', 'Descubriendo nuevos horizontes', '¡Sigues explorando!'),
(4, 'Practicante', 500, 'fa-running', '#f59e0b', 'Práctica constante', 'La constancia es tu fortaleza'),
(5, 'Competente', 1000, 'fa-medal', '#ec4899', 'Dominio creciente', '¡Tu dedicación da frutos!'),
(6, 'Experto', 2000, 'fa-crown', '#ef4444', 'Maestría en desarrollo', 'Eres ejemplo de superación'),
(7, 'Maestro', 5000, 'fa-gem', '#7c3aed', 'Nivel máximo alcanzado', '¡Eres un verdadero maestro!')
ON DUPLICATE KEY UPDATE level_name=VALUES(level_name);

-- Tabla 5: Catálogo de logros
CREATE TABLE IF NOT EXISTS achievements (
    id INT PRIMARY KEY AUTO_INCREMENT,
    achievement_key VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    icon_class VARCHAR(100),
    color_hex VARCHAR(7),
    category ENUM('puntos', 'nivel', 'racha', 'categoria', 'especial') DEFAULT 'puntos',
    requirement_type VARCHAR(50),
    requirement_value INT,
    rarity ENUM('comun', 'raro', 'epico', 'legendario') DEFAULT 'comun',
    reward_points INT DEFAULT 0,
    is_secret BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla 6: Logros desbloqueados por coachees
CREATE TABLE IF NOT EXISTS coachee_achievements (
    id INT PRIMARY KEY AUTO_INCREMENT,
    coachee_id INT NOT NULL,
    achievement_id INT NOT NULL,
    unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_viewed BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (coachee_id) REFERENCES coachees(id) ON DELETE CASCADE,
    FOREIGN KEY (achievement_id) REFERENCES achievements(id) ON DELETE CASCADE,
    UNIQUE KEY unique_achievement_per_coachee (coachee_id, achievement_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla 7: Rachas de actividad
CREATE TABLE IF NOT EXISTS coachee_streaks (
    coachee_id INT PRIMARY KEY,
    current_streak INT DEFAULT 0,
    last_activity_date DATE,
    longest_streak INT DEFAULT 0,
    total_active_days INT DEFAULT 0,
    FOREIGN KEY (coachee_id) REFERENCES coachees(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Inicializar puntos para coachees existentes
INSERT IGNORE INTO coachee_points (coachee_id, total_points, current_level, points_in_level, points_to_next_level)
SELECT id, 0, 1, 0, 100 FROM coachees;

-- Inicializar rachas para coachees existentes
INSERT IGNORE INTO coachee_streaks (coachee_id, current_streak, last_activity_date, longest_streak, total_active_days)
SELECT id, 0, NULL, 0, 0 FROM coachees;

-- ============================================
-- VERIFICACIÓN
-- ============================================
-- SELECT COUNT(*) as total_tables FROM information_schema.tables 
-- WHERE table_schema = DATABASE() 
-- AND table_name IN ('coachee_points', 'task_points_config', 'point_transactions', 'levels_system', 'achievements', 'coachee_achievements', 'coachee_streaks');
-- 
-- SELECT * FROM levels_system ORDER BY level_number;
-- SELECT COUNT(*) FROM coachee_points;
