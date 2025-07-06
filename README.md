# Assessment Platform

Plataforma web para evaluaciones de asertividad con roles de coach y coachee.

## Características

- Sistema de autenticación por roles (admin, coach, coachee)
- Evaluaciones de asertividad con 10 preguntas
- Dashboard para coaches con análisis de progreso
- Dashboard para coachees con resultados personalizados
- Gráficos de progreso temporal
- Sistema de invitaciones para coachees

## Tecnologías

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Base de datos**: SQLite
- **Gráficos**: Chart.js
- **Autenticación**: Flask-Login
- **Deployment**: Render

## Estructura del proyecto

- `app_complete.py` - Aplicación principal Flask
- `coach_analysis.py` - Módulo de análisis para coaches
- `wsgi_production.py` - Configuración WSGI para producción
- `templates/` - Plantillas HTML
- `requirements.txt` - Dependencias Python
- `render.yaml` - Configuración de deployment

## Instalación

1. Instalar dependencias:
```bash
pip install -r requirements.txt
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