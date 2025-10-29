# 🚀 Despliegue de instacoach.cl en Railway

## ✅ Configuración Completada

### 1. Código Listo ✅
- ✅ Puerto dinámico configurado: `PORT = int(os.environ.get('PORT', 8080))`
- ✅ CORS configurado para instacoach.cl
- ✅ PostgreSQL automático en Railway
- ✅ SSL automático (HTTPS)
- ✅ Healthcheck endpoint: `/api/status`

### 2. Archivos de Configuración ✅
```
✅ wsgi_production.py    → Entrada principal de Railway
✅ Procfile              → web: python wsgi_production.py
✅ railway.toml          → Configuración de despliegue
✅ nixpacks.toml         → Build configuration
✅ requirements.txt      → Dependencias Python
```

## 📋 Pasos para Activar instacoach.cl

### Paso 1: Configurar Dominio en Railway

1. **Ir a tu proyecto en Railway**
   - 🔗 https://railway.app/
   - Selecciona tu proyecto "assessment-platform"

2. **Agregar Dominio Personalizado**
   ```
   Settings → Networking → Custom Domain
   
   Click "Add Domain"
   Ingresa: instacoach.cl
   ```

3. **Railway te dará un CNAME target**
   ```
   Ejemplo: assessment-platform-production-xxxx.up.railway.app
   ```
   ⚠️ **IMPORTANTE**: Copia este valor exacto

### Paso 2: Configurar DNS de instacoach.cl

Ve al panel de administración de tu proveedor de dominio .cl y configura:

#### Opción A: Si tu proveedor soporta ANAME/ALIAS (Recomendado)
```dns
Tipo: ANAME o ALIAS
Host: @
Valor: assessment-platform-production-xxxx.up.railway.app
TTL: 3600
```

#### Opción B: Si solo soporta CNAME (más común)
```dns
# Para www
Tipo: CNAME
Host: www
Valor: assessment-platform-production-xxxx.up.railway.app
TTL: 3600

# Para dominio raíz (redirect)
Tipo: URL Redirect (301)
Host: @
Destino: https://www.instacoach.cl
```

### Paso 3: Variables de Entorno en Railway

Verifica que estén configuradas en Railway:

```bash
# OBLIGATORIAS
SECRET_KEY=railway-production-key-assessment-platform-2025-secure
DATABASE_URL=(automático por Railway)
FLASK_ENV=production
FLASK_DEBUG=False

# RECOMENDADAS
PYTHONUNBUFFERED=1
FORCE_ADMIN_CREATION=true
LOG_LEVEL=INFO
```

### Paso 4: Esperar Propagación DNS

⏳ **Tiempo estimado**: 5 minutos a 24 horas

Verificar propagación:
```bash
# Verificar DNS
dig instacoach.cl
dig www.instacoach.cl

# Verificar que apunte a Railway
nslookup instacoach.cl
```

### Paso 5: Verificar Despliegue

Una vez propagado el DNS:

```bash
# 1. Verificar API
curl https://instacoach.cl/api/status

# Respuesta esperada:
# {"status": "ok", "message": "API funcionando correctamente"}

# 2. Verificar SSL
curl -I https://instacoach.cl

# Debe mostrar:
# HTTP/2 200
# server: Railway

# 3. Verificar en navegador
# https://instacoach.cl
```

## 🎯 Endpoints Principales de instacoach.cl

```
🏠 Inicio:              https://instacoach.cl/
👤 Login Coachee:       https://instacoach.cl/participant-access
👨‍🏫 Login Coach:        https://instacoach.cl/coach-login
🔧 Admin:               https://instacoach.cl/admin-login
📊 API Status:          https://instacoach.cl/api/status
```

## 🔐 Usuarios de Prueba (después del despliegue)

Railway creará automáticamente:

### Admin
```
URL: https://instacoach.cl/admin-login
Email: admin@instacoach.cl
Password: admin123
```

### Coach
```
URL: https://instacoach.cl/coach-login
Email: coach@instacoach.cl
Password: coach123
```

## 📊 Monitoreo

### Ver Logs en Tiempo Real
```bash
# Instalar Railway CLI
npm install -g @railway/cli

# Login
railway login

# Ver logs
railway logs
railway logs --follow
```

### Verificar Estado
```bash
# Healthcheck
watch -n 5 'curl -s https://instacoach.cl/api/status | jq'

# Headers
curl -I https://instacoach.cl
```

## 🐛 Troubleshooting

### Problema: 502 Bad Gateway
**Causa**: Railway no puede conectar con la app
**Solución**:
```bash
1. Verificar logs: railway logs
2. Verificar PORT: railway variables
3. Reiniciar: railway up
```

### Problema: DNS no resuelve
**Causa**: DNS no propagado o mal configurado
**Solución**:
```bash
1. Verificar DNS: dig instacoach.cl
2. Esperar 24 horas para propagación global
3. Verificar configuración en proveedor de dominio
```

### Problema: SSL no funciona
**Causa**: Railway necesita tiempo para provisionar certificado
**Solución**:
- Esperar 10-15 minutos después de agregar dominio
- Railway provisiona SSL automáticamente
- Verificar en Railway Dashboard que dice "Active"

### Problema: Base de datos no conecta
**Causa**: DATABASE_URL no configurada
**Solución**:
```bash
1. Ir a Railway Dashboard
2. Agregar PostgreSQL plugin
3. Railway configurará DATABASE_URL automáticamente
```

## ✨ Características Activadas

- ✅ **HTTPS Automático**: SSL por Let's Encrypt
- ✅ **PostgreSQL**: Base de datos en Railway
- ✅ **Auto-deploy**: Push a main → Deploy automático
- ✅ **Healthcheck**: Monitoreo automático
- ✅ **Logs**: Centralizados en Railway
- ✅ **Backups**: PostgreSQL con backups automáticos
- ✅ **Scaling**: Ready para scale horizontal

## 📈 Próximos Pasos Post-Despliegue

1. ✅ **Verificar acceso**: https://instacoach.cl
2. 🔐 **Cambiar passwords** de admin y coach
3. 📧 **Configurar email** (si necesitas notificaciones)
4. 📊 **Configurar analytics** (Google Analytics, etc.)
5. 🔔 **Configurar monitoring** (UptimeRobot, Pingdom)
6. 📱 **Testing mobile** en dispositivos reales
7. 🎨 **Personalizar branding** con logo de instacoach

## 🎉 ¡Listo!

Tu plataforma **Instacoach** está lista para producción en:

🌐 **https://instacoach.cl**

---

**Última actualización**: Octubre 29, 2025
**Estado**: ✅ Producción Ready
**Dominio**: instacoach.cl
**Hosting**: Railway
**Base de Datos**: PostgreSQL (Railway)
**SSL**: Automático
