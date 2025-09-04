# Deploy en Railway - Plataforma de Evaluación

## 🚀 DEPLOY RAILWAY - Assessment Platform

## ✅ Configuración optimizada para Railway

### 📋 Archivos de configuración actualizados:

1. **`Procfile`** - Comando gunicorn optimizado
2. **`wsgi_production.py`** - Entry point WSGI con logging
3. **`railway.toml`** - Configuración Railway robusta
4. **`nixpacks.toml`** - Build configuration sin conflictos
5. **`railway.env`** - Variables de entorno completas
6. **`check_railway_deploy.py`** - Script de verificación

### 🔧 Problemas corregidos:

#### ❌ Problemas anteriores:
- Conflicto entre `Procfile` y `nixpacks.toml` start command
- WSGI entry point sin logging adecuado
- Health check en ruta básica sin JSON
- Timeout muy bajo (120s)
- Falta de configuración de workers

#### ✅ Soluciones implementadas:
- Procfile con configuración gunicorn robusta
- WSGI con logging detallado para Railway
- Health check en `/api/status` con JSON
- Timeout aumentado a 300s
- Worker class sync configurado
- Preload de aplicación habilitado

### 🚀 PASOS PARA DEPLOY

#### 1. Verificar configuración local:
```bash
python3 check_railway_deploy.py
```

#### 2. Instalar Railway CLI:
```bash
npm install -g @railway/cli
```

#### 3. Login en Railway:
```bash
railway login
```

#### 4. Crear/conectar proyecto:
```bash
# Nuevo proyecto
railway new

# O conectar existente
railway link
```

#### 5. Configurar variables de entorno:
```bash
railway variables set FLASK_ENV=production
railway variables set FLASK_DEBUG=False
railway variables set FORCE_ADMIN_CREATION=true
railway variables set SECRET_KEY="railway-production-key-assessment-platform-2025-secure"
railway variables set PYTHONUNBUFFERED=1
railway variables set LOG_LEVEL=INFO
```

#### 6. Agregar PostgreSQL:
```bash
railway add postgresql
```
⚠️ Railway configura `DATABASE_URL` automáticamente

#### 7. Deploy:
```bash
railway up
```

#### 8. Verificar deploy:
```bash
# Ver logs
railway logs

# Abrir en navegador
railway open

# Ver variables
railway variables
```

### 🔍 URLs de verificación:

Una vez deployado, verificar:
- `https://tu-app.railway.app/` - Página principal
- `https://tu-app.railway.app/api/status` - Health check
- `https://tu-app.railway.app/coachee-dashboard` - Dashboard
- `https://tu-app.railway.app/admin` - Panel admin

### 🛠️ Troubleshooting:

#### Error: "Application failed to start"
```bash
# Ver logs detallados
railway logs --tail

# Verificar variables
railway variables

# Redeploy
railway up --detach
```

#### Error: "Database connection failed"
```bash
# Verificar PostgreSQL
railway add postgresql

# Ver variables de BD
railway variables | grep DATABASE
```

#### Error: "Health check timeout"
```bash
# Verificar endpoint
curl https://tu-app.railway.app/api/status

# Aumentar timeout en railway.toml si es necesario
```

### 📊 Configuración de Gunicorn:

```bash
# Procfile actual:
web: gunicorn wsgi_production:application --bind 0.0.0.0:$PORT --workers 1 --worker-class sync --timeout 300 --keepalive 2 --max-requests 1000 --max-requests-jitter 100 --preload --log-level info
```

**Explicación:**
- `--workers 1` - Un worker para Railway (recursos limitados)
- `--worker-class sync` - Worker síncrono, más estable
- `--timeout 300` - 5 minutos timeout para requests largos
- `--keepalive 2` - Mantener conexiones vivas
- `--max-requests 1000` - Reiniciar worker después de 1000 requests
- `--preload` - Precargar aplicación para mejor rendimiento
- `--log-level info` - Logging detallado

### 🔒 Seguridad en producción:

✅ **Configurado:**
- `DEBUG=False`
- `FLASK_ENV=production`
- SECRET_KEY seguro
- PostgreSQL en lugar de SQLite
- Variables de entorno protegidas

### 📝 Notas importantes:

1. **Base de datos**: Railway usa PostgreSQL automáticamente
2. **Puerto**: Railway asigna `$PORT` dinámicamente
3. **Dominio**: Railway proporciona subdominio automático
4. **SSL**: Railway incluye HTTPS automáticamente
5. **Logs**: Accesibles via `railway logs`

### � Checklist post-deploy:

- [ ] App inicia sin errores
- [ ] Health check responde (`/api/status`)
- [ ] Base de datos conecta
- [ ] Usuarios admin/coach creados
- [ ] Evaluaciones cargadas
- [ ] Dashboard funciona
- [ ] SSL/HTTPS activo
- [ ] Logs muestran inicialización exitosa

### 🆘 Comandos de emergencia:

```bash
# Restart deployment
railway up --detach

# Ver logs en tiempo real
railway logs --tail

# Conectar a base de datos
railway connect postgresql

# Rollback (si disponible)
railway rollback

# Variables de entorno
railway variables set KEY=value
railway variables unset KEY
```
