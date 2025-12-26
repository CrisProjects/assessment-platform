# SOLUCIÓN: Evaluaciones No Disponibles en Producción

## 🔴 Problema
El dashboard del coach en producción muestra "no evaluaciones disponibles" en la sección Evaluaciones, cuando debería mostrar las evaluaciones por defecto del sistema (IDs 1-6 mínimo).

## 🔍 Diagnóstico

### Causa Raíz
La base de datos de producción (PostgreSQL) tiene evaluaciones con:
- `status = NULL` en lugar de `status = 'published'`
- `is_active = NULL` o `is_active = False` en lugar de `is_active = True`

Esto ocurre porque:
1. Las columnas `status`, `coach_id` y `category` fueron agregadas recientemente al modelo Assessment
2. La migración para agregar estas columnas NO fue ejecutada en producción
3. Las evaluaciones existentes en producción tienen valores `NULL` por defecto
4. El endpoint `/api/coach/available-assessments` filtra por `is_active=True`, excluyendo registros con `NULL`

### Cómo Funciona Localmente
- Base de datos: `instance/assessments.db` (SQLite)
- 11 evaluaciones totales
- 9 activas con `status='published'` y `is_active=True`
- El endpoint retorna 9 evaluaciones correctamente

### Por Qué Falla en Producción
- Base de datos: PostgreSQL en Railway
- Evaluaciones existentes tienen `status=NULL` e `is_active=NULL`
- Query `WHERE is_active = True` excluye registros `NULL`
- Resultado: 0 evaluaciones disponibles

## ✅ Soluciones

### Opción 1: Ejecutar Migración Completa (RECOMENDADO)

Este script agrega las columnas faltantes Y actualiza los datos existentes:

```bash
# En producción (Railway), conectado a la base de datos correcta:
DATABASE_URL="<tu-database-url-postgresql>" python3 migration_add_assessment_fields_postgres.py
```

**Qué hace:**
1. Verifica si las columnas `status`, `coach_id`, `category` existen
2. Si no existen, las agrega con valores por defecto
3. Crea índices para performance
4. **CRÍTICO**: Ejecuta `UPDATE assessment SET status = 'published' WHERE status IS NULL`
5. Muestra estadísticas finales

**Salida esperada:**
```
🔧 Adding 0 new columns... (si ya existen)
🔄 Updating existing assessments to 'published' status...
   ✅ Updated X existing records
📈 Current assessment statistics:
      • published: X assessment(s)
```

### Opción 2: Quick Fix (Rápido pero menos completo)

Si las columnas YA EXISTEN pero los datos están mal:

```bash
# En producción:
DATABASE_URL="<tu-database-url-postgresql>" python3 fix_available_assessments.py
```

**Qué hace:**
1. Verifica cuántas evaluaciones existen
2. Ejecuta `UPDATE assessment SET is_active = True`
3. Ejecuta `UPDATE assessment SET status = 'published' WHERE status IS NULL`
4. Muestra antes/después

**Salida esperada:**
```
🔧 Step 1: Setting is_active=True for all assessments...
   ✅ Updated X assessments
🔧 Step 2: Setting status='published' for NULL status...
   ✅ Updated X assessments
```

### Opción 3: Query Manual SQL

Si prefieres ejecutar SQL directamente en la consola de Railway:

```sql
-- 1. Ver estado actual
SELECT id, title, is_active, status 
FROM assessment 
ORDER BY id 
LIMIT 10;

-- 2. Actualizar is_active
UPDATE assessment 
SET is_active = TRUE 
WHERE is_active IS NULL OR is_active = FALSE;

-- 3. Actualizar status
UPDATE assessment 
SET status = 'published' 
WHERE status IS NULL OR status = '';

-- 4. Verificar resultado
SELECT 
    status, 
    COUNT(*) as count 
FROM assessment 
GROUP BY status;

SELECT 
    is_active, 
    COUNT(*) as count 
FROM assessment 
GROUP BY is_active;
```

## 🩺 Diagnóstico en Producción

Para diagnosticar el problema SIN hacer cambios:

```bash
# Ejecutar diagnóstico (solo lectura):
DATABASE_URL="<tu-database-url-postgresql>" python3 diagnose_available_assessments.py
```

**Verifica:**
1. Estructura de la tabla assessment
2. Total de evaluaciones
3. Distribución de is_active
4. Distribución de status
5. Simula la query del endpoint
6. Identifica valores NULL
7. Provee recomendaciones específicas

**Ejemplo de salida con problema:**
```
📊 3. IS_ACTIVE DISTRIBUTION:
   • is_active=NULL: 11 assessments    ← PROBLEMA!

📊 4. STATUS DISTRIBUTION:
   • status='NULL': 11 assessments     ← PROBLEMA!

📊 6. SIMULATING /api/coach/available-assessments QUERY:
   Query: SELECT * FROM assessment WHERE is_active = True
   Result: 0 assessments               ← PROBLEMA!

   ⚠️  PROBLEM FOUND: No active assessments!
```

## 📋 Pasos Recomendados

### Para Producción (Railway):

1. **Verificar el problema:**
   ```bash
   # Conectar a la base de datos de producción
   DATABASE_URL="<railway-postgres-url>" python3 diagnose_available_assessments.py
   ```

2. **Si el diagnóstico muestra status=NULL o is_active=NULL:**
   ```bash
   # Ejecutar la migración completa
   DATABASE_URL="<railway-postgres-url>" python3 migration_add_assessment_fields_postgres.py
   ```

3. **Verificar que se aplicó correctamente:**
   ```bash
   # Ejecutar diagnóstico de nuevo
   DATABASE_URL="<railway-postgres-url>" python3 diagnose_available_assessments.py
   ```
   
   Debería mostrar:
   ```
   📊 3. IS_ACTIVE DISTRIBUTION:
      • is_active=1: X assessments    ← ✅ CORRECTO

   📊 4. STATUS DISTRIBUTION:
      • status='published': X assessments    ← ✅ CORRECTO

   📊 6. SIMULATING /api/coach/available-assessments QUERY:
      Result: X assessments           ← ✅ CORRECTO
   ```

4. **Reiniciar la aplicación en Railway:**
   - Ve al dashboard de Railway
   - Click en tu servicio
   - Click en "Restart" o realiza un nuevo deploy

5. **Probar en producción:**
   - Abre el dashboard del coach
   - Ve a la sección "Evaluaciones"
   - Verifica que aparezcan las evaluaciones disponibles

### Para Local (Verificación):

El ambiente local YA FUNCIONA correctamente:
```bash
# Verificar local (debe mostrar todo OK)
python3 diagnose_available_assessments.py
```

## 🔧 Scripts Disponibles

| Script | Propósito | Lectura/Escritura |
|--------|-----------|-------------------|
| `diagnose_available_assessments.py` | Diagnóstico completo | Solo lectura |
| `migration_add_assessment_fields_postgres.py` | Migración completa | Escritura (seguro) |
| `fix_available_assessments.py` | Fix rápido de datos | Escritura (mínimo) |

## ⚠️ Notas Importantes

1. **Respaldo de Base de Datos**: Aunque las operaciones son seguras (solo UPDATE), Railway hace respaldos automáticos, pero verifica antes.

2. **Entorno Local vs Producción**:
   - Local: `instance/assessments.db` (SQLite) - Ya funciona
   - Producción: PostgreSQL en Railway - Necesita fix

3. **DATABASE_URL en Railway**:
   - Obtenerlo de: Railway Dashboard → Variables → DATABASE_URL
   - Formato: `postgresql://user:pass@host:port/database`
   - El script convierte automáticamente `postgres://` a `postgresql://`

4. **Verificación Sin Riesgo**:
   - `diagnose_available_assessments.py` es 100% seguro (solo SELECT)
   - Ejecutarlo primero para confirmar el problema

## 🎯 Resultado Esperado

Después de aplicar la solución:

**Antes:**
```json
{
  "success": true,
  "assessments": [],
  "total": 0,
  "message": "Se encontraron 0 evaluaciones disponibles"
}
```

**Después:**
```json
{
  "success": true,
  "assessments": [
    {"id": 1, "title": "Evaluación de Asertividad", ...},
    {"id": 2, "title": "Evaluación DISC", ...},
    {"id": 3, "title": "Evaluación de Inteligencia Emocional", ...},
    ...
  ],
  "total": 6,
  "message": "Se encontraron 6 evaluaciones disponibles"
}
```

## 📞 Soporte

Si después de ejecutar estos scripts el problema persiste:

1. Revisar logs del servidor: `heroku logs --tail` o Railway logs
2. Verificar errores de conexión a base de datos
3. Confirmar que la variable `DATABASE_URL` es correcta
4. Verificar que la aplicación se reinició después del fix

---

**Última actualización**: 2025-01-06
**Estado local**: ✅ Funcionando (9 evaluaciones)
**Estado producción**: 🔴 Necesita fix (0 evaluaciones)
