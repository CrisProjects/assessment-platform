# 👥 USUARIOS CREADOS POR DEFECTO - ASSESSMENT PLATFORM

## 📊 RESUMEN
La aplicación crea automáticamente **3 usuarios de prueba** al inicializarse por primera vez, uno para cada rol del sistema.

## 🛡️ **ADMINISTRADOR DE PLATAFORMA**

### Datos del Usuario:
- **Nombre Completo**: Platform Administrator
- **Username**: `admin`
- **Email**: `admin@assessment.com`
- **Rol**: `platform_admin`
- **Estado**: Activo ✅

### Credenciales de Acceso:
```
Username: admin
Password: admin123
```

### URLs de Acceso:
- Login específico: `/admin-login`
- Dashboard: `/platform-admin-dashboard`

### Funcionalidades:
- ✅ Crear y administrar coaches
- ✅ Ver estadísticas de la plataforma
- ✅ Gestionar usuarios globales
- ✅ Cambiar su propia contraseña

---

## 🎯 **COACH DE PRUEBA**

### Datos del Usuario:
- **Nombre Completo**: Coach de Prueba
- **Username**: `coach`
- **Email**: `coach@assessment.com`
- **Rol**: `coach`
- **Estado**: Activo ✅

### Credenciales de Acceso:
```
Email: coach@assessment.com
Password: coach123
```

### URLs de Acceso:
- Login específico: `/coach-login`
- Dashboard: `/coach-dashboard`

### Funcionalidades:
- ✅ Crear invitaciones para coachees
- ✅ Ver estadísticas de sus coachees
- ✅ Monitorear progreso de evaluaciones
- ✅ Cambiar su propia contraseña

---

## 📚 **COACHEE DE PRUEBA**

### Datos del Usuario:
- **Nombre Completo**: Coachee de Prueba
- **Username**: `coachee`
- **Email**: `coachee@assessment.com`
- **Rol**: `coachee`
- **Estado**: Activo ✅

### Credenciales de Acceso:
```
Email: coachee@assessment.com
Password: coachee123
```

### URLs de Acceso:
- Dashboard: `/coachee-dashboard`

### Funcionalidades:
- ✅ Completar evaluaciones de asertividad
- ✅ Ver sus resultados
- ✅ Acceso temporal mediante invitaciones

---

## 🔧 PROCESO DE CREACIÓN AUTOMÁTICA

### Cuándo se Crean:
Los usuarios se crean automáticamente al ejecutar la aplicación por primera vez mediante la función `auto_initialize_database()`.

### Lógica de Creación:

#### 1. **Administrador (admin)**
```python
if not admin_user:
    admin_user = User(
        username='admin',
        email='admin@assessment.com',
        full_name='Platform Administrator',
        role='platform_admin'
    )
    admin_user.set_password('admin123')
```

#### 2. **Coach**
- Se verifica si ya existe un coach con email `coach@assessment.com`
- Si existe, se actualiza su contraseña a `coach123`
- La gestión de coaches está deshabilitada para preservar datos reales

#### 3. **Coachee**
```python
if not coachee_user:
    coachee_user = User(
        username='coachee',
        email='coachee@assessment.com',
        full_name='Coachee de Prueba',
        role='coachee'
    )
    coachee_user.set_password('coachee123')
```

## 🚀 TESTING RÁPIDO

### Para probar la aplicación:

1. **Como Administrador:**
   ```
   Ir a: http://localhost:5001/admin-login
   Username: admin
   Password: admin123
   ```

2. **Como Coach:**
   ```
   Ir a: http://localhost:5001/coach-login
   Email: coach@assessment.com
   Password: coach123
   ```

3. **Como Coachee:**
   ```
   Ir a: http://localhost:5001/coachee-dashboard
   Email: coachee@assessment.com
   Password: coachee123
   ```

## ⚠️ NOTAS IMPORTANTES

### Seguridad:
- Las contraseñas están encriptadas usando `werkzeug.security`
- En producción, estas contraseñas deben cambiarse
- Los usuarios de prueba solo existen para desarrollo

### Base de Datos:
- Fecha de creación: 2025-07-06 20:44:53
- Base de datos: SQLite (`assessments.db`)
- Total de usuarios actuales: **3**

### Estados:
- ✅ Todos los usuarios están activos
- ✅ Todas las contraseñas han sido verificadas
- ✅ Sistema de roles funcionando correctamente

---

**Última verificación**: 2025-07-13  
**Estado**: ✅ Todos los usuarios verificados y funcionales
