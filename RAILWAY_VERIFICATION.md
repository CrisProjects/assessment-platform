# 🚀 Cómo Verificar Deploy en Railway

## 📍 Paso 1: Acceder a Railway Dashboard

1. Ve a: https://railway.app
2. Inicia sesión con tu cuenta
3. Busca y abre el proyecto: **assessment-platform** (o el nombre que le hayas dado)

---

## 🔍 Paso 2: Verificar Estado del Deploy

### En la vista principal del proyecto:

```
┌─────────────────────────────────────┐
│  🚂 Railway Dashboard               │
├─────────────────────────────────────┤
│                                     │
│  📦 assessment-platform             │
│                                     │
│  ┌───────────────────────────────┐ │
│  │ ● Active  (debe ser verde)   │ │
│  │ Commit: 789fc5a               │ │
│  │ Branch: main                  │ │
│  └───────────────────────────────┘ │
│                                     │
│  Pestañas:                          │
│  [Settings] [Variables] [Deployments] [Metrics] │
└─────────────────────────────────────┘
```

### ✅ Verificaciones importantes:

1. **Status debe ser "Active"** (círculo verde)
2. **Último commit debe coincidir** con tu último push
   ```bash
   # En tu terminal local:
   git log -1 --oneline
   # Compara con el commit en Railway
   ```

3. **Branch debe ser "main"**

---

## 📋 Paso 3: Revisar Logs del Deploy

### Ir a la pestaña "Deployments":

1. Click en **"Deployments"** en el menú superior
2. Ver el deployment más reciente
3. Click en el deployment para ver detalles

### Qué buscar en los logs:

```
✅ Buenos logs:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Building...
✓ Installing dependencies from requirements.txt
✓ Running: python wsgi_production.py
✓ Application started successfully
✓ Listening on port 8080

❌ Malos logs (errores comunes):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✗ ModuleNotFoundError: No module named 'xxx'
  → Falta dependencia en requirements.txt
  
✗ NameError: name 'xxx' is not defined
  → Error en código Python
  
✗ Connection refused
  → Problema con base de datos

✗ Bind to port failed
  → Problema de configuración de puerto
```

---

## 🌐 Paso 4: Obtener URL de Producción

### En Railway Dashboard:

1. En la vista del proyecto, busca la sección **"Settings"**
2. Baja hasta **"Domains"**
3. Verás algo como:
   ```
   🌐 Public Domain
   https://assessment-platform-production.up.railway.app
   
   [Copy URL] [Generate Domain]
   ```

4. **Copia esta URL** - la necesitarás para testing

---

## 🧪 Paso 5: Verificar que los Cambios Están Desplegados

### A. Test básico del API:

```bash
# En tu terminal:
curl https://TU_URL_RAILWAY/api/status

# Debe retornar:
{
  "status": "success",
  "message": "Assessment Platform API is running",
  "version": "2.0.0"
}
```

### B. Test en el navegador:

1. Abre: `https://TU_URL_RAILWAY/coach-login`
2. **Importante:** Haz **Hard Reload** para evitar cache:
   - Mac: `Cmd + Shift + R`
   - Windows: `Ctrl + Shift + R`
   - O abre en modo Incógnito

3. Abre la **Consola del navegador** (F12 → Console)
4. Busca este mensaje:
   ```
   📦 [COACH-FEED] Script version: 2026-01-17-22:23
   ```
   
   ✅ Si lo ves = versión actualizada cargada
   ❌ Si no lo ves = cache o deploy pendiente

### C. Test funcional:

1. Haz login con tu usuario coach
2. Deberías redirigir a `/coach-feed`
3. Los datos deberían cargar sin errores
4. En la consola verás logs como:
   ```
   🚀 [COACH-FEED] Inicializando aplicación...
   📡 [COACH-FEED] Respuesta recibida: 200 OK
   ✅ [COACH-FEED] Contenido cargado: 2 items
   ```

---

## 🔧 Paso 6: Verificar Variables de Entorno

Si algo no funciona, verifica las variables:

1. Ve a **Settings** → **Variables**
2. Asegúrate de tener:
   ```
   DATABASE_URL=postgresql://...
   SECRET_KEY=tu_secret_key
   FLASK_ENV=production
   ```

3. Si falta alguna, agrégala y redeploy

---

## 🐛 Troubleshooting

### Problema: "Deploy exitoso pero no veo cambios"

**Solución:**
```bash
# 1. Verificar que el commit está en Railway
git log origin/main -1

# 2. Hard reload en el navegador
Cmd+Shift+R (Mac) o Ctrl+Shift+R (Windows)

# 3. O forzar redeploy:
echo "$(date)" > RAILWAY_DEPLOY.trigger
git add RAILWAY_DEPLOY.trigger
git commit -m "trigger: Force redeploy"
git push
```

### Problema: "Error 500 en producción"

**Solución:**
```bash
# Ver logs de Railway
railway logs --filter error

# O en Dashboard:
Deployments → Latest → View Logs
```

Buscar:
- NameError
- ModuleNotFoundError
- Connection errors

### Problema: "Deployment failed"

**Solución:**
1. Revisar logs de build en Railway
2. Verificar que requirements.txt está actualizado
3. Verificar que wsgi_production.py existe
4. Verificar que Procfile está correcto

### Problema: "Cambios en templates no se ven"

**Causas comunes:**
1. Cache del navegador
2. Railway no reinició
3. Cache-busting no está funcionando

**Solución:**
```bash
# 1. Verificar cache-busting:
grep "get_file_version" templates/coach_feed.html

# 2. Agregar timestamp al script:
# Buscar en el template y cambiar versión

# 3. Hard reload en navegador
```

---

## 📊 Métricas y Monitoreo

### En Railway Dashboard → Metrics:

- **CPU Usage**: Debe estar < 80%
- **Memory Usage**: Debe estar < 512MB
- **Response Time**: Debe estar < 500ms
- **Request Count**: Ver tráfico

Si algo está alto:
1. Revisar queries lentas en base de datos
2. Optimizar código
3. Considerar upgrade de plan

---

## ✅ Checklist de Verificación Final

Antes de cerrar:

- [ ] Deploy status: Active ✅
- [ ] Último commit coincide ✅
- [ ] URL de producción funciona ✅
- [ ] Hard reload realizado ✅
- [ ] Consola sin errores ✅
- [ ] Login funciona ✅
- [ ] Datos cargan correctamente ✅
- [ ] Versión del script correcta ✅
- [ ] Logs sin errores críticos ✅

---

## 🔗 Enlaces Útiles

- **Railway Dashboard**: https://railway.app
- **Docs Railway**: https://docs.railway.app
- **GitHub Repo**: https://github.com/CrisProjects/assessment-platform
- **Script de verificación local**: `./verify_deploy.sh`
- **Checklist completo**: `DEPLOY_CHECKLIST.md`

---

## 💡 Tips Finales

1. **Siempre haz hard reload** después de un deploy
2. **Guarda la URL de Railway** en algún lugar accesible
3. **Monitorea logs** los primeros 5 minutos después del deploy
4. **Ten un rollback plan** si algo falla
5. **Documenta errores** que encuentres para futuras referencias

---

## 🆘 Ayuda Rápida

```bash
# Ver estado local
./verify_deploy.sh

# Ver últimos commits
git log -5 --oneline

# Ver diferencias con producción
git diff origin/main

# Forzar redeploy
echo "$(date)" > RAILWAY_DEPLOY.trigger && \
git add . && \
git commit -m "trigger: Force redeploy" && \
git push
```
