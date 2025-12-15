# 📧 Configuración de Email para Recuperación de Contraseña

## ✅ Estado Actual

El sistema de recuperación de contraseña está **completamente implementado** y listo para usar. Solo requiere configurar las credenciales SMTP.

---

## 🔧 Configuración en Local (Desarrollo)

### Paso 1: Obtener Contraseña de Aplicación de Google

1. **Accede a tu cuenta de Google** (`support@instacoach.cl`)

2. **Habilita la verificación en 2 pasos**:
   - Ve a: https://myaccount.google.com/security
   - Busca "Verificación en 2 pasos"
   - Actívala si no está habilitada

3. **Genera una contraseña de aplicación**:
   - Ve a: https://myaccount.google.com/apppasswords
   - Si no ves esta opción, asegúrate de que la verificación en 2 pasos esté activa
   - Selecciona:
     - **App**: Correo
     - **Dispositivo**: Otro (nombre personalizado) → escribe "Instacoach Recovery"
   - Haz clic en **Generar**
   - **Copia la contraseña de 16 caracteres** (sin espacios)

### Paso 2: Configurar Variables de Entorno Locales

1. **Crea un archivo `.env`** en la raíz del proyecto (si no existe):
   ```bash
   cp .env.example .env
   ```

2. **Edita el archivo `.env`** y agrega:
   ```env
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=support@instacoach.cl
   SMTP_PASSWORD=xxxx xxxx xxxx xxxx  # Tu contraseña de aplicación de 16 caracteres
   SENDER_EMAIL=support@instacoach.cl
   SENDER_NAME=Instacoach - Soporte
   ```

3. **Guarda el archivo** (asegúrate de que `.env` esté en `.gitignore`)

### Paso 3: Probar Localmente

1. **Reinicia el servidor Flask**:
   ```bash
   python3 start_server_stable.py
   ```

2. **Prueba el flujo**:
   - Ve al login del admin
   - Haz clic en "¿Olvidaste tu contraseña?"
   - Ingresa el email del admin
   - Revisa la bandeja de entrada del email

---

## 🚀 Configuración en Producción (Railway)

### Paso 1: Configurar Variables de Entorno en Railway

1. **Accede a tu proyecto en Railway**:
   - Ve a: https://railway.app/dashboard

2. **Selecciona tu proyecto** → **Settings** → **Variables**

3. **Agrega las siguientes variables**:
   
   | Variable | Valor |
   |----------|-------|
   | `SMTP_SERVER` | `smtp.gmail.com` |
   | `SMTP_PORT` | `587` |
   | `SMTP_USERNAME` | `support@instacoach.cl` |
   | `SMTP_PASSWORD` | `xxxx xxxx xxxx xxxx` (tu contraseña de aplicación) |
   | `SENDER_EMAIL` | `support@instacoach.cl` |
   | `SENDER_NAME` | `Instacoach - Soporte` |

4. **Haz clic en "Deploy"** o espera el auto-deploy

### Paso 2: Verificar que Funciona

1. **Ve a tu sitio en producción**
2. **Accede al login del admin**
3. **Haz clic en "¿Olvidaste tu contraseña?"**
4. **Ingresa el email del admin** (debe tener un email válido configurado)
5. **Revisa el email recibido**

---

## 📋 Requisitos Previos

Antes de que funcione la recuperación de contraseña, asegúrate de:

### ✅ El admin debe tener un email válido

1. **Inicia sesión como admin**
2. **Haz clic en "Editar Perfil"** (botón nuevo en el header)
3. **Agrega o actualiza tu email** a un email real que uses
4. **Guarda los cambios**

### ✅ Variables de entorno configuradas

- En **local**: archivo `.env` con credenciales
- En **Railway**: variables de entorno en Settings

---

## 🎯 Flujo Completo de Recuperación

### Para el Usuario:

1. **Va al login** (`/admin-login`)
2. **Hace clic en "¿Olvidaste tu contraseña?"**
3. **Ingresa su email** y hace clic en "Enviar"
4. **Recibe un email** con un enlace de recuperación
5. **Hace clic en el enlace** (válido por 1 hora)
6. **Ingresa su nueva contraseña** (con validación en tiempo real)
7. **Confirma la contraseña**
8. **Hace clic en "Restablecer Contraseña"**
9. **¡Listo!** Puede iniciar sesión con la nueva contraseña

### Detrás de Escenas:

1. Sistema genera token seguro de 32 bytes
2. Token se guarda en BD con expiración de 1 hora
3. Email HTML profesional se envía vía SMTP
4. Usuario accede con token válido
5. Sistema valida token (no expirado, no usado)
6. Usuario establece nueva contraseña
7. Token se marca como usado
8. Evento se registra en logs de seguridad

---

## 🔒 Características de Seguridad

✅ **Tokens criptográficamente seguros** (32 bytes, `secrets.token_urlsafe`)
✅ **Expiración de 1 hora** (tokens antiguos no funcionan)
✅ **Un solo uso** (tokens no se pueden reutilizar)
✅ **Validación de contraseña fuerte** (8+ chars, mayúscula, minúscula, número, símbolo)
✅ **No revela emails existentes** (respuesta genérica siempre)
✅ **Registro de eventos** en security_log
✅ **Email HTML profesional** con instrucciones claras
✅ **Versión texto plano** como fallback

---

## 🎨 Email Template

El email que se envía incluye:

- **Header con branding** de Instacoach
- **Botón prominente** "Restablecer Contraseña"
- **URL alternativa** por si el botón no funciona
- **Advertencias de seguridad** (1 hora de validez, un solo uso)
- **Footer con soporte** (support@instacoach.cl)
- **Diseño responsive** (se ve bien en móvil y desktop)

---

## 🐛 Troubleshooting

### Problema: "SMTP_PASSWORD no configurado"

**Solución**: Agrega la variable de entorno `SMTP_PASSWORD` con tu contraseña de aplicación de Google.

### Problema: "Authentication failed"

**Soluciones**:
1. Verifica que la contraseña de aplicación sea correcta (16 caracteres sin espacios)
2. Asegúrate de que la verificación en 2 pasos esté activa
3. Genera una nueva contraseña de aplicación
4. Verifica que `SMTP_USERNAME` sea `support@instacoach.cl`

### Problema: No llega el email

**Soluciones**:
1. Revisa la carpeta de SPAM
2. Verifica que el email del admin esté correcto
3. Revisa los logs de Railway para ver errores SMTP
4. Verifica que las variables de entorno estén configuradas correctamente

### Problema: "Token inválido o expirado"

**Causas**:
- El token tiene más de 1 hora
- El token ya fue usado
- El enlace está incompleto

**Solución**: Solicita un nuevo enlace de recuperación

---

## 📝 Próximos Pasos Opcionales

1. **Extender a roles coach y coachee**:
   - Usar la misma función `send_password_reset_email()`
   - Crear endpoints similares para cada rol
   - Agregar enlaces en sus respectivos logins

2. **Personalizar templates de email**:
   - Agregar logo de Instacoach
   - Personalizar colores corporativos
   - Agregar firma personalizada

3. **Rate limiting**:
   - Limitar a 3 intentos por hora por email
   - Prevenir abuso del sistema

4. **Notificaciones adicionales**:
   - Email de confirmación cuando la contraseña se cambie
   - Alerta si hay múltiples intentos fallidos

---

## ✅ Checklist de Implementación

- [x] Código de recuperación implementado
- [x] Endpoints API creados
- [x] Templates HTML (formularios, invalid token)
- [x] Migración de base de datos ejecutada
- [x] Función SMTP configurada
- [x] Email HTML profesional diseñado
- [x] Documentación completa
- [ ] Variables de entorno configuradas en Railway
- [ ] Email del admin configurado
- [ ] Prueba en producción realizada

---

## 📞 Soporte

Si necesitas ayuda configurando el sistema, contacta a support@instacoach.cl

---

**Última actualización**: 14 de diciembre de 2025
