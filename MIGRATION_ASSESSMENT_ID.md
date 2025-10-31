# Instrucciones para Ejecutar Migración en Railway

## Problema
La tabla `invitation` en PostgreSQL (Railway) no tiene la columna `assessment_id`, lo que causa el siguiente error al crear invitaciones:

```
psycopg2.errors.UndefinedColumn) column "assessment_id" of relation "invitation" does not exist
```

## Solución

### Opción 1: Ejecutar script de migración via Railway CLI

1. **Instalar Railway CLI** (si no lo tienes):
   ```bash
   npm i -g @railway/cli
   ```

2. **Login en Railway**:
   ```bash
   railway login
   ```

3. **Vincular al proyecto**:
   ```bash
   railway link
   ```

4. **Ejecutar el script de migración**:
   ```bash
   railway run python3 add_assessment_id_to_invitation.py
   ```

### Opción 2: Ejecutar SQL directamente en Railway Dashboard

1. Ve a tu proyecto en Railway Dashboard
2. Abre la pestaña "Data" de tu base de datos PostgreSQL
3. Ejecuta el siguiente SQL:

```sql
-- Agregar columna assessment_id
ALTER TABLE invitation 
ADD COLUMN assessment_id INTEGER;

-- Agregar foreign key constraint
ALTER TABLE invitation
ADD CONSTRAINT fk_invitation_assessment 
    FOREIGN KEY (assessment_id) 
    REFERENCES assessment(id) 
    ON DELETE SET NULL;

-- Crear índice para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_invitation_assessment_id 
ON invitation(assessment_id);
```

### Opción 3: SSH a Railway y ejecutar el script

1. **Conectarse via SSH**:
   ```bash
   railway shell
   ```

2. **Ejecutar el script**:
   ```bash
   python3 add_assessment_id_to_invitation.py
   ```

## Verificación

Después de ejecutar la migración, verifica que la columna existe:

```sql
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name='invitation' AND column_name='assessment_id';
```

Deberías ver:
```
column_name    | data_type
---------------+-----------
assessment_id  | integer
```

## Notas Importantes

- ✅ El script detecta automáticamente si es PostgreSQL o SQLite
- ✅ Verifica si la columna ya existe antes de agregarla
- ✅ Crea un índice para mejorar el rendimiento
- ✅ Es seguro ejecutar el script múltiples veces (idempotente)
- ⚠️ No elimina ningún dato existente
- ⚠️ Los valores de `assessment_id` serán NULL para invitaciones antiguas

## Después de la Migración

Una vez completada la migración, la funcionalidad de "Invitar Coachee" con asignación de evaluación funcionará correctamente sin errores.
