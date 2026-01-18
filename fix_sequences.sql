-- ============================================================================
-- FIX: Resincronizar secuencias de PostgreSQL
-- Error: duplicate key value violates unique constraint "assessment_pkey"
-- ============================================================================

-- 1. Ver el problema actual
SELECT 
    'assessment' as tabla,
    MAX(id) as max_id_tabla,
    (SELECT last_value FROM assessment_id_seq) as valor_secuencia;

-- 2. Resincronizar secuencia de assessment
SELECT setval('assessment_id_seq', (SELECT MAX(id) FROM assessment) + 1, false);

-- 3. Verificar que se corrigió
SELECT 
    'assessment' as tabla,
    MAX(id) as max_id_tabla,
    (SELECT last_value FROM assessment_id_seq) as valor_secuencia;

-- 4. Actualizar categorías NULL mientras estamos aquí
UPDATE assessment SET category = 'Liderazgo'
WHERE (category IS NULL OR category = 'Otros')
AND (LOWER(title) LIKE '%lider%' OR LOWER(title) LIKE '%liderazgo%' OR LOWER(title) LIKE '%gestion%');

UPDATE assessment SET category = 'Personalidad'
WHERE (category IS NULL OR category = 'Otros')
AND (LOWER(title) LIKE '%personalidad%' OR LOWER(title) LIKE '%disc%' OR LOWER(title) LIKE '%temperamento%');

UPDATE assessment SET category = 'Inteligencia Emocional'
WHERE (category IS NULL OR category = 'Otros')
AND (LOWER(title) LIKE '%emocional%' OR LOWER(title) LIKE '%empatia%');

UPDATE assessment SET category = 'Trabajo en Equipo'
WHERE (category IS NULL OR category = 'Otros')
AND (LOWER(title) LIKE '%equipo%' OR LOWER(title) LIKE '%colaboracion%' OR LOWER(title) LIKE '%teamwork%');

UPDATE assessment SET category = 'Crecimiento Empresarial'
WHERE (category IS NULL OR category = 'Otros')
AND (LOWER(title) LIKE '%empresarial%' OR LOWER(title) LIKE '%negocio%' OR LOWER(title) LIKE '%ventas%');

UPDATE assessment SET category = 'Otros' WHERE category IS NULL;

-- 5. Ver resumen de categorías
SELECT category, COUNT(*) as cantidad
FROM assessment
WHERE is_active = true
GROUP BY category
ORDER BY cantidad DESC;

