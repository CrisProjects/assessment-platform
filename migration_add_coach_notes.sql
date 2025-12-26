-- ============================================================================
-- Migración: Agregar campo coach_notes a tabla user
-- Plataforma: EfectoCoach Assessment Platform
-- Base de Datos: PostgreSQL (Railway)
-- Fecha: 2024
-- ============================================================================

-- Descripción:
-- Este campo permite a los coaches guardar notas privadas sobre sus coachees.
-- Las notas pueden incluir observaciones de sesiones, avances, objetivos, etc.

-- IMPORTANTE: 
-- Ejecutar este script en Railway Console ANTES de hacer deploy del código nuevo

-- ============================================================================
-- PASO 1: Verificar si la columna ya existe
-- ============================================================================

SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name='user' AND column_name='coach_notes';

-- Si la consulta anterior devuelve una fila, la columna YA EXISTE.
-- En ese caso, NO ejecutar el siguiente comando.

-- ============================================================================
-- PASO 2: Agregar columna coach_notes (solo si NO existe)
-- ============================================================================

ALTER TABLE "user" 
ADD COLUMN coach_notes TEXT;

-- ============================================================================
-- PASO 3: Verificar que se agregó correctamente
-- ============================================================================

SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name='user' AND column_name='coach_notes';

-- Resultado esperado:
-- column_name  | data_type | is_nullable
-- -------------|-----------|------------
-- coach_notes  | text      | YES

-- ============================================================================
-- PASO 4: (Opcional) Ver estructura completa de la tabla user
-- ============================================================================

SELECT 
    column_name, 
    data_type, 
    character_maximum_length,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name='user'
ORDER BY ordinal_position;

-- ============================================================================
-- NOTAS:
-- ============================================================================
-- 
-- 1. La columna es NULLABLE (permite NULL), por lo que no afecta registros existentes
-- 2. Tipo TEXT permite notas extensas sin límite de caracteres
-- 3. No se necesitan índices ya que las notas no se usan en búsquedas
-- 4. Solo los coaches pueden ver y editar sus propias notas
-- 5. Las notas no son visibles para los coachees
--
-- ============================================================================
-- ROLLBACK (en caso de necesitar revertir):
-- ============================================================================
-- 
-- ALTER TABLE "user" DROP COLUMN coach_notes;
--
-- ⚠️  ADVERTENCIA: Esto eliminará permanentemente todas las notas guardadas
-- ============================================================================
