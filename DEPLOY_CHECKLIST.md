# ✅ Checklist de Deploy a Producción

## Pre-Deploy

### 1. Verificación de Código
- [ ] Todos los cambios están commiteados
- [ ] No hay conflictos pendientes
- [ ] Tests locales pasan (si aplica)
- [ ] Servidor local funciona correctamente

### 2. Verificación de Git
```bash
# Ejecutar script de verificación
./verify_deploy.sh

# O manualmente:
git status                    # Debe estar limpio
git log -5                    # Ver últimos commits
git diff origin/main          # No debe haber diferencias
```

### 3. Verificación de Archivos Críticos
- [ ] `app.py` - Backend principal
- [ ] `wsgi_production.py` - Entry point para Railway
- [ ] `Procfile` - Comando de inicio
- [ ] `railway.toml` - Configuración Railway
- [ ] `requirements.txt` - Dependencias
- [ ] Templates modificados tienen cache-busting

### 4. Push a GitHub
```bash
git add -A
git commit -m "Descripción clara del cambio"
git push origin main
```

## Durante Deploy

### 5. Monitoreo en Railway
1. Ir a https://railway.app
2. Seleccionar proyecto "assessment-platform"
3. Ver pestaña "Deployments"
4. Verificar:
   - [ ] Build Status: Success
   - [ ] Deploy Status: Active
   - [ ] Logs sin errores críticos

### 6. Verificar Variables de Entorno
En Railway Dashboard → Settings → Variables:
- [ ] `DATABASE_URL` configurada
- [ ] `SECRET_KEY` configurada
- [ ] `FLASK_ENV=production`
- [ ] Otras variables necesarias

## Post-Deploy

### 7. Verificación de Producción

#### A. Health Check
```bash
curl https://TU_URL_RAILWAY/api/status
# Debe retornar: {"status": "success", ...}
```

#### B. Test de Login
1. Abrir: `https://TU_URL_RAILWAY/coach-login`
2. Login con credenciales de prueba
3. Verificar redirección a `/coach-feed`

#### C. Verificar Consola del Navegador
1. Abrir DevTools (F12) → Console
2. Buscar mensajes de versión:
   - `📦 [COACH-FEED] Script version: 2026-01-17-22:23`
3. No deben haber errores 404 o 500

#### D. Verificar Funcionalidades Críticas
- [ ] Dashboard carga correctamente
- [ ] Feed muestra contenido
- [ ] API endpoints responden (my-coachees, my-content)
- [ ] Navegación entre páginas funciona

### 8. Verificar Cache-Busting
1. Hard reload: `Cmd+Shift+R` (Mac) o `Ctrl+Shift+R` (Windows)
2. Verificar que se cargan archivos con `?v=...`
3. En Network tab: verificar que CSS/JS tienen versión

### 9. Logs de Producción
```bash
# Ver logs en Railway
railway logs --follow

# O en Dashboard:
# Railway → Tu Proyecto → Deployments → View Logs
```

## Troubleshooting

### Si no se ven los cambios:
1. **Verificar que el commit está pusheado**
   ```bash
   git log origin/main -5
   ```

2. **Verificar que Railway deployó**
   - Dashboard debe mostrar el commit más reciente
   - Status debe ser "Active"

3. **Limpiar cache del navegador**
   - Hard reload: `Cmd+Shift+R`
   - O abrir en modo incógnito

4. **Forzar redeploy en Railway**
   ```bash
   # Tocar archivo trigger
   echo "$(date)" > RAILWAY_DEPLOY.trigger
   git add RAILWAY_DEPLOY.trigger
   git commit -m "trigger: Force redeploy $(date +%Y%m%d-%H%M%S)"
   git push
   ```

5. **Verificar logs de error**
   ```bash
   railway logs --filter error
   ```

### Si hay error 500:
1. Revisar logs de Railway
2. Verificar variables de entorno
3. Verificar conexión a base de datos
4. Rollback a versión anterior si es necesario

### Si los datos no cargan:
1. Abrir consola del navegador (F12)
2. Ver tab Network → buscar requests fallidas
3. Ver tab Console → buscar errores JS
4. Verificar que APIs devuelven JSON válido

## Comandos Útiles

```bash
# Verificar deploy
./verify_deploy.sh

# Ver estado actual
git status
git log origin/main -5

# Forzar push
git push --force-with-lease origin main

# Ver diferencias con producción
git diff origin/main

# Rollback a commit anterior
git reset --hard COMMIT_HASH
git push --force-with-lease origin main
```

## Notas Importantes

⚠️ **Railway despliega automáticamente al detectar push a `main`**

⚠️ **Los cambios en templates HTML NO requieren rebuild, solo redeploy**

⚠️ **Cache-busting es crítico para que los usuarios vean cambios**

⚠️ **Siempre verificar logs después del deploy**

## Historial de Deploys Recientes

| Fecha | Commit | Descripción | Status |
|-------|--------|-------------|--------|
| 2026-01-17 | 851212b | Cache-busting coach_feed | ✅ |
| 2026-01-17 | 70f36a8 | Fix api_coach_my_coachees | ✅ |
| 2026-01-17 | 38c8f0e | Logging mejorado | ✅ |
| 2026-01-17 | 90ac4aa | Mejoras mobile + redirect | ✅ |
