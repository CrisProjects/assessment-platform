# 🚨 Migración de Documentos en Producción

## Problema Detectado

Los documentos creados **antes** del commit `baf81bd` usan URLs antiguas que dependen de la sesión del coach:

```
❌ URL Antigua: /api/coach/documents/6/view
✅ URL Nueva:   /api/coachee/documents/6/files/X/preview
```

**Síntoma**: Al hacer clic en documentos antiguos aparece:
```json
{"error":"Archivo no encontrado en el servidor"}
```

## Causa Raíz

1. Las URLs antiguas apuntan al endpoint `@coach_session_required`
2. Las rutas de archivo pueden estar incorrectas en producción (paths locales vs producción)
3. Los documentos creados después de la migración funcionan correctamente

## Solución

Ejecutar el script `migrate_production_documents.py` **directamente en Railway**.

### Opción 1: Railway CLI (Recomendado)

```bash
# Desde tu máquina local con Railway CLI instalado
railway link  # Si no está vinculado
railway run python migrate_production_documents.py
```

### Opción 2: Railway Dashboard

1. Ve al dashboard de Railway
2. Abre la terminal del servicio
3. Ejecuta:
```bash
python migrate_production_documents.py
```

### Opción 3: Deployment Hook

Si tienes problemas con las opciones anteriores, puedes hacer push del script y ejecutarlo como tarea one-time:

```bash
git add migrate_production_documents.py MIGRATION_PRODUCTION_DOCS.md
git commit -m "feat: Script migración documentos producción"
git push origin main
```

Luego en Railway:
```bash
railway run python migrate_production_documents.py
```

## Qué hace el script

1. **Verifica rutas de archivos**
   - Detecta rutas locales (ej: `/Users/cristiangaldames/...`)
   - Las convierte a rutas de producción (ej: `/app/uploads/documents/...`)
   - Detecta si deberían estar en S3

2. **Migra URLs de Content**
   - Busca todos los `Content` con URLs antiguas
   - Extrae el `document_id` de la URL
   - Busca el `DocumentFile` correspondiente
   - Crea nueva URL: `/api/coachee/documents/{doc_id}/files/{file_id}/preview`

3. **Verifica estado**
   - Muestra todos los documentos activos
   - Indica si los archivos existen
   - Muestra las URLs de Content asociadas

## Ejemplo de Ejecución

```
🚀 MIGRACIÓN DE DOCUMENTOS EN PRODUCCIÓN
============================================================

📋 VERIFICACIÓN DE DOCUMENTOS
============================================================

📁 Total documentos activos: 3

Documento #6: Plan de Desarrollo Q1
  Coach: 1 → Coachee: 2
  Creado: 2025-01-03 15:30:00
  📄 Archivo: plan_desarrollo.pdf
     Ruta: /Users/cristiangaldames/Projects/.../xxx.pdf
     ❌ ARCHIVO NO ENCONTRADO
  📋 Content #8: /api/coach/documents/6/view

¿Deseas continuar? (escribe 'si' para confirmar): si

PASO 1: CORRECCIÓN DE RUTAS DE ARCHIVO
============================================================

🔄 Archivo 4:
   Antigua: /Users/cristiangaldames/Projects/assessment-platform1/uploads/documents/abc123.pdf
   Nueva:   /app/uploads/documents/abc123.pdf

✅ Corregidas 1 rutas de archivo

PASO 2: MIGRACIÓN DE URLs DE CONTENT
============================================================

📊 Encontrados 1 contenidos para migrar

✅ Content 8:
   Documento: 6
   Antigua: /api/coach/documents/6/view
   Nueva:   /api/coachee/documents/6/files/4/preview

============================================================
✅ Migración completada exitosamente!
📊 Migrados: 1, ⏭️  Omitidos: 0, ❌ Errores: 0
============================================================
```

## Post-Migración

Después de ejecutar el script:

1. ✅ Los coachees podrán ver documentos sin necesidad de sesión del coach
2. ✅ Los documentos aparecerán correctamente en "Mi Contenido"
3. ✅ La vista previa PDF funcionará en coachee-feed
4. ✅ Las rutas de archivo estarán corregidas para producción

## Rollback

Si algo sale mal, el script NO elimina datos. Solo actualiza:
- `Content.content_url` 
- `DocumentFile.file_path`

Puedes revertir manualmente desde Railway console:

```sql
-- Ver contenidos migrados
SELECT id, title, content_url FROM content WHERE content_type = 'document';

-- Revertir un content específico (si es necesario)
UPDATE content 
SET content_url = '/api/coach/documents/6/view' 
WHERE id = 8;
```

## Notas Importantes

- ⚠️ El script es **idempotente**: puedes ejecutarlo múltiples veces sin problemas
- ✅ No afecta documentos nuevos (ya tienen URLs correctas)
- ✅ No elimina datos, solo actualiza URLs y rutas
- 🔍 Muestra una verificación completa antes de aplicar cambios
- 💾 Hace commit solo si hay cambios exitosos

## Validación

Después de la migración, verifica en la app:

1. Cierra sesión del coach
2. Inicia sesión como coachee
3. Ve a "Mi Contenido"
4. Haz clic en el documento antiguo (ID 6)
5. Debería abrirse correctamente ✅

## Contacto

Si encuentras problemas durante la migración, revisa los logs de Railway o consulta este documento.
