# 🚨 MIGRACIÓN URGENTE: Agregar campo 'category' a development_plan

## Problema
Error en producción al crear planes de desarrollo:
```
column "category" of relation "development_plan" does not exist
```

## Solución - Ejecutar en Railway

### Opción 1: Desde Railway CLI (Recomendado)

```bash
# 1. Instalar Railway CLI (si no lo tienes)
npm i -g @railway/cli

# 2. Login a Railway
railway login

# 3. Conectar al proyecto
railway link

# 4. Ejecutar la migración
railway run python3 run_production_migration.py
```

### Opción 2: Desde Railway Dashboard

1. Ve a tu proyecto en Railway Dashboard
2. Abre la pestaña "Deployments"
3. Click en el deployment activo
4. Click en "View Logs"
5. En la sección de settings, busca "Service Settings"
6. Agrega un "One-off Command":
   ```bash
   python3 run_production_migration.py
   ```

### Opción 3: SQL Directo en PostgreSQL

Si tienes acceso directo a la base de datos:

```sql
-- Agregar columna category
ALTER TABLE development_plan 
ADD COLUMN IF NOT EXISTS category VARCHAR(20) DEFAULT 'personal';

-- Agregar columna milestones (si no existe)
ALTER TABLE development_plan 
ADD COLUMN IF NOT EXISTS milestones TEXT DEFAULT '[]';

-- Verificar
SELECT column_name, data_type, character_maximum_length, column_default
FROM information_schema.columns
WHERE table_name = 'development_plan'
AND column_name IN ('category', 'milestones')
ORDER BY ordinal_position;
```

### Opción 4: Desde Railway Shell

```bash
# 1. Abrir shell en Railway
railway shell

# 2. Ejecutar migración
python3 run_production_migration.py
```

## Verificación

Después de ejecutar la migración, verifica que funcionó:

```bash
railway run python3 -c "from app import app, db; from sqlalchemy import text; \
with app.app_context(): \
    result = db.session.execute(text(\"SELECT column_name FROM information_schema.columns WHERE table_name='development_plan' AND column_name IN ('category', 'milestones')\")).fetchall(); \
    print('Columnas encontradas:', [r[0] for r in result])"
```

## Archivos de migración

- `add_category_to_development_plan.py` - Agrega campo category
- `add_milestones_field.py` - Agrega campo milestones
- `run_production_migration.py` - Ejecuta todas las migraciones

## Notas importantes

- ⚠️ **NO ejecutes estos scripts en desarrollo sin antes hacer backup**
- ✅ Los scripts son idempotentes (seguros de ejecutar múltiples veces)
- ✅ Tienen validación para evitar errores si la columna ya existe
- ✅ Usan transacciones para rollback automático en caso de error
