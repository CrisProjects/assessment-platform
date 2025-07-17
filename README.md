# Assessment Platform

Plataforma web completa para evaluaciones de asertividad con sistema de roles multinivel.

## Características Principales

- **Sistema de autenticación por roles**: Platform Admin, Coach, Coachee
- **Evaluaciones de asertividad**: 10 preguntas con escala Likert
- **Dashboard para Platform Admin**: Gestión de coaches y estadísticas globales
- **Dashboard para Coaches**: Análisis de progreso de coachees, invitaciones, gestión de tareas
- **Dashboard para Coachees**: Resultados personalizados, evaluaciones y tareas asignadas
- **Gráficos de progreso temporal**: Visualización con Chart.js
- **Sistema de invitaciones**: Para registrar coachees vía email
- **Gestión de tareas**: Asignación y seguimiento por categorías de asertividad
- **Sesiones temporales**: Para evaluaciones sin registro completo

## Tecnologías

- **Backend**: Flask 3.0.0 (Python)
- **Frontend**: HTML5, CSS3, JavaScript ES6, Bootstrap 5.3.2
- **Base de datos**: SQLite con índices optimizados
- **Gráficos**: Chart.js
- **Autenticación**: Flask-Login con sesiones seguras
- **CORS**: Flask-CORS para frontend separado
- **Deployment**: Render + Vercel
- **Servidor de producción**: Gunicorn

## Estructura del Proyecto

```
assessment-platform1/
├── app_complete.py          # Aplicación principal Flask (3000+ líneas)
├── wsgi_production.py       # Configuración WSGI optimizada para producción
├── templates/              # Plantillas HTML
│   ├── base.html           # Template base con navbar responsive
│   ├── dashboard_selection.html  # Página principal de selección
│   ├── admin_dashboard.html      # Dashboard de administrador
│   ├── coach_dashboard.html      # Dashboard de coach
│   └── coachee_dashboard.html    # Dashboard de coachee
├── instance/               # Base de datos
│   └── assessments.db      # SQLite con datos de producción
├── testing/               # Archivos de testing organizados
├── render.yaml            # Configuración para Render
├── requirements.txt       # Dependencias Python
├── runtime.txt           # Versión de Python
├── Procfile             # Configuración de Heroku/Render
└── migrate_indexes.py   # Script de migración de índices
```

## Instalación y Desarrollo

### Desarrollo Local

1. **Clonar el repositorio**:
```bash
git clone <repository-url>
cd assessment-platform1
```

2. **Crear entorno virtual**:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate     # Windows
```

3. **Instalar dependencias**:
```bash
pip install -r requirements.txt
```

4. **Configurar variables de entorno**:
```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

5. **Inicializar base de datos**:
```bash
python init_complete_db.py
```

6. **Ejecutar aplicación**:
```bash
python app_complete.py
```

La aplicación estará disponible en `http://localhost:5002`

## Deployment

### Render (Recomendado)

1. Conectar repositorio a Render
2. Usar configuración de `render.yaml`
3. Las variables de entorno se configuran automáticamente
4. Deploy automático con cada push a `main`

### Variables de Entorno Requeridas

- `SECRET_KEY`: Clave secreta para sesiones (auto-generada en Render)
- `FLASK_ENV`: `production` para producción
- `DATABASE_URL`: Ruta de base de datos (automática en SQLite)
- `ALLOWED_ORIGINS`: URLs permitidas para CORS

## Usuarios por Defecto

### Administrador de Plataforma
- **Usuario**: `admin`
- **Email**: `admin@assessment.com`
- **Contraseña**: `admin123`

### Coach de Prueba
- **Email**: `coach@assessment.com`
- **Contraseña**: `coach123`

### Coachee de Prueba
- **Email**: `coachee@assessment.com`
- **Contraseña**: `coachee123`

## API Endpoints Principales

- `GET /` - Página de selección de dashboard
- `POST /api/login` - Autenticación general
- `POST /api/admin/login` - Login de administrador
- `POST /api/coach/login` - Login de coach
- `GET /api/admin/platform-stats` - Estadísticas de plataforma
- `GET /api/coach/coachees` - Lista de coachees del coach
- `POST /api/coach/invite` - Enviar invitación a coachee
- `POST /api/assessment/start` - Iniciar evaluación
- `POST /api/assessment/submit` - Enviar respuestas de evaluación

## Características de Seguridad

- Contraseñas hasheadas con Werkzeug
- Sesiones seguras con Flask-Login
- CORS configurado para dominios específicos
- Validación de entrada en todos los endpoints
- Tokens únicos para invitaciones
- Configuración de cookies seguras en producción

## Contribución

1. Fork el proyecto
2. Crear feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a branch (`git push origin feature/AmazingFeature`)
5. Abrir Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT.
```

2. Ejecutar la aplicación:
```bash
python app_complete.py
```

3. Acceder a `http://localhost:5000`

## Usuarios por defecto

- **Admin**: admin@assessment.com / admin123
- **Coach**: coach@assessment.com / coach123  
- **Coachee**: coachee@assessment.com / coachee123

## Deployment

La aplicación está configurada para deployment en Render usando `render.yaml`.