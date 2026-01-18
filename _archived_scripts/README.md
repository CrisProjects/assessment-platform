# Scripts Esenciales Archivados

**Fecha de Archivo:** 10 de enero de 2026

## Scripts de Migración Críticos (11 archivos)

Estos scripts contienen la lógica de migración de datos entre sistemas y cambios de schema. **NO ELIMINAR** sin verificar que no se necesitarán para rollback.

### Migraciones de Base de Datos
- `migrate_sqlite_to_postgres.py` - Migración inicial SQLite → PostgreSQL
- `migrate_railway_remote.py` - Migración a Railway
- `migrate_assessment_fields.py` - Migración de campos de assessment
- `migrate_assessments_to_railway.py` - Migración de assessments a Railway
- `migrate_document_urls.py` - Migración de URLs de documentos
- `migrate_production_documents.py` - Migración de documentos en producción

### Migraciones de Schema
- `migration_add_assessment_draft_fields.py`
- `migration_add_assessment_fields_postgres.py`
- `migration_add_assessment_history.py`

## Scripts de Corrección de Datos (4 archivos)

Scripts que corrigieron problemas en producción. Útiles como referencia si surgen problemas similares.

- `fix_assessment_history_percentages.py` - Corrección de porcentajes en historial
- `fix_available_assessments.py` - Corrección de evaluaciones disponibles
- `fix_document_urls.py` - Corrección de URLs de documentos
- `fix_postgres_password_field.py` - Corrección de campo password en PostgreSQL

## Scripts de Configuración (1 archivo)

- `create_development_plan_table.py` - Creación de tabla de planes de desarrollo

---

**Total:** 14 archivos esenciales (reducción del 83% desde 83 archivos originales)

## Cuándo usar estos scripts

- **Migraciones:** Si necesitas hacer rollback o migrar a nuevo ambiente
- **Fixes:** Como referencia para problemas similares en datos
- **Schema:** Para entender cambios históricos de la base de datos
