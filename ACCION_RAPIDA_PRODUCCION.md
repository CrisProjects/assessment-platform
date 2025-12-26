# ⚡ ACCIÓN RÁPIDA: Arreglar Evaluaciones en Producción

## 🎯 Problema Identificado

El dashboard del coach en **producción** muestra "no evaluaciones disponibles" porque:
- Las columnas `status` e `is_active` de las evaluaciones tienen valores `NULL`
- El endpoint filtra por `is_active = True`, excluyendo los registros `NULL`
- La migración de columnas NO se ejecutó en la base de datos de producción

## ✅ Solución Rápida (3 pasos)

### 1. Conectarse a Railway y obtener DATABASE_URL

```bash
# En tu terminal local, desde el directorio del proyecto:
# Opción A: Si tienes Railway CLI instalado
railway variables

# Opción B: Manualmente desde el dashboard
# Ve a: Railway Dashboard → Tu Proyecto → Variables → DATABASE_URL
# Copia el valor completo (empieza con postgres:// o postgresql://)
```

### 2. Ejecutar el diagnóstico (verificar problema)

```bash
# Reemplaza <DATABASE_URL> con el valor real
DATABASE_URL="<tu-database-url>" python3 diagnose_available_assessments.py
```

**Deberías ver:**
```
📊 3. IS_ACTIVE DISTRIBUTION:
   • is_active=NULL: X assessments    ← CONFIRMA EL PROBLEMA

📊 6. SIMULATING /api/coach/available-assessments QUERY:
   Result: 0 assessments              ← CONFIRMA EL PROBLEMA
```

### 3. Ejecutar la migración (aplicar fix)

```bash
# Usa el mismo DATABASE_URL del paso 1
DATABASE_URL="<tu-database-url>" python3 migration_add_assessment_fields_postgres.py
```

**Deberías ver:**
```
✅ AUTO-INIT: Contraseña coach verificada
🔧 Step 2: Setting status='published' for NULL status...
   ✅ Updated X assessments
💾 Changes committed
```

### 4. Reiniciar Railway

```bash
# Opción A: Railway CLI
railway restart

# Opción B: Dashboard
# Ve a: Railway Dashboard → Tu Servicio → Settings → Restart
```

### 5. Verificar que funciona

1. Abre el dashboard del coach en producción
2. Ve a la sección "Evaluaciones"  
3. Deberías ver las evaluaciones disponibles (mínimo 6)

## 📚 Documentación Completa

Para más detalles, consulta: `FIX_EVALUACIONES_DISPONIBLES.md`

## 🆘 Si algo sale mal

El script es seguro (solo hace UPDATE), pero si necesitas revertir:

```sql
-- Conecta a Railway Database directamente y ejecuta:
UPDATE assessment SET is_active = NULL WHERE coach_id IS NULL;
UPDATE assessment SET status = NULL WHERE coach_id IS NULL;
```

## ⏰ Tiempo estimado

- Diagnóstico: 10 segundos
- Fix: 15 segundos  
- Verificación: 30 segundos
- **Total: ~1 minuto**

---

**Estado actual:**
- ✅ Local: Funcionando (9 evaluaciones)
- 🔴 Producción: Necesita fix (0 evaluaciones)

**Después del fix:**
- ✅ Local: Funcionando (9 evaluaciones)
- ✅ Producción: Funcionando (6+ evaluaciones)
