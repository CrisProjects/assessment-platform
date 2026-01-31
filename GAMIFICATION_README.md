# 🎮 Sistema de Gamificación - README

## 📋 Descripción

Sistema de gamificación que permite a los coaches asignar puntos a tareas y a los coachees ganar puntos, subir de nivel y desbloquear logros.

---

## 🚀 Cómo Usar Esta Implementación

### ✅ PASO 1: Verificar Estado Actual
```bash
# Verificar que el servidor está corriendo
python3 verify_system.py
```

**Resultado esperado:** Todas las verificaciones deben pasar ✅

---

### 💾 PASO 2: Hacer Backup
```bash
# Ejecutar backup automático
./backup_gamification.sh
```

**Resultado esperado:** 
- Carpeta `backups/gamification/` creada
- BD respaldada
- app.py respaldado
- Templates respaldados

---

### 🗄️ PASO 3: Ejecutar Migración de Base de Datos

**Opción A: MySQL desde terminal**
```bash
mysql -u root -p instacoach_db < migrations/migration_gamification_base.sql
```

**Opción B: Desde Railway/Producción**
1. Abrir Railway Dashboard
2. Ir a la base de datos
3. Ejecutar el contenido de `migration_gamification_base.sql`

**Verificar tablas creadas:**
```sql
SHOW TABLES LIKE '%coachee_points%';
SHOW TABLES LIKE '%task_points_config%';
SHOW TABLES LIKE '%levels_system%';
SELECT * FROM levels_system;
SELECT COUNT(*) FROM coachee_points;
```

---

### ✅ PASO 4: Verificar que Todo Funciona
```bash
# Verificar después de la migración
python3 verify_system.py
```

**Pruebas manuales:**
1. ✅ Entrar como coach: `http://localhost:5002/coach/dashboard-v2`
2. ✅ Entrar como coachee: `http://localhost:5002/coachee/dashboard`
3. ✅ Crear una tarea (debe funcionar igual que antes)
4. ✅ Ver evaluaciones (debe funcionar igual)
5. ✅ No debe haber errores en consola

---

## 📁 Archivos Creados en Etapa 0

```
assessment-platform1/
├── migrations/
│   └── migration_gamification_base.sql    # SQL de tablas base
├── backups/
│   └── gamification/                      # Backups automáticos
├── backup_gamification.sh                 # Script de backup
├── verify_system.py                       # Script de verificación
├── GAMIFICATION_PROGRESS.md               # Tracking de progreso
└── GAMIFICATION_README.md                 # Este archivo
```

---

## 🗂️ Estructura de Base de Datos

### Tablas Creadas

1. **`coachee_points`** - Puntos y nivel de cada coachee
2. **`task_points_config`** - Configuración de puntos por tarea
3. **`point_transactions`** - Historial de puntos ganados
4. **`levels_system`** - Definición de niveles (1-7)
5. **`achievements`** - Catálogo de logros
6. **`coachee_achievements`** - Logros desbloqueados
7. **`coachee_streaks`** - Rachas de días activos

### Niveles Definidos

| Nivel | Nombre | Puntos Requeridos | Color |
|-------|--------|-------------------|-------|
| 1 | Novato | 0 | Verde |
| 2 | Aprendiz | 100 | Azul |
| 3 | Explorador | 250 | Púrpura |
| 4 | Practicante | 500 | Naranja |
| 5 | Competente | 1000 | Rosa |
| 6 | Experto | 2000 | Rojo |
| 7 | Maestro | 5000 | Púrpura Oscuro |

---

## 🔄 Rollback (Si algo sale mal)

### Opción 1: Rollback de Base de Datos
```bash
# Encontrar el backup más reciente
ls -lt backups/gamification/

# Restaurar BD
mysql -u root -p instacoach_db < backups/gamification/db_backup_YYYYMMDD_HHMMSS.sql
```

### Opción 2: Eliminar Tablas Nuevas
```sql
DROP TABLE IF EXISTS coachee_achievements;
DROP TABLE IF EXISTS achievements;
DROP TABLE IF EXISTS point_transactions;
DROP TABLE IF EXISTS task_points_config;
DROP TABLE IF EXISTS coachee_streaks;
DROP TABLE IF EXISTS coachee_points;
DROP TABLE IF EXISTS levels_system;
```

### Opción 3: Restaurar app.py
```bash
cp backups/gamification/app_backup_YYYYMMDD_HHMMSS.py app.py
```

---

## ✅ Checklist de Etapa 0

- [x] Archivo SQL creado
- [x] Script de backup creado
- [x] Script de verificación creado
- [x] Documento de tracking creado
- [ ] Backup ejecutado
- [ ] Migración SQL ejecutada
- [ ] Verificación post-migración pasada
- [ ] Sistema funciona igual que antes

---

## 📞 Soporte

Si encuentras algún problema:

1. **NO continuar** con las siguientes etapas
2. Ejecutar rollback según la guía arriba
3. Verificar logs en `gamification_verification.log`
4. Revisar `GAMIFICATION_PROGRESS.md` para detalles

---

## 🎯 Próximos Pasos

Una vez que la **Etapa 0** esté completa y verificada:

1. ✅ Confirmar que todas las tablas fueron creadas
2. ✅ Confirmar que el sistema funciona igual
3. ✅ Commit de los cambios
4. 🚀 Pasar a **Etapa 1: Base de Datos**

---

**Última actualización:** 31 Enero 2026  
**Desarrollador:** Cristian Galdames
