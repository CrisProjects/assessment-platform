# Plataforma de Evaluación de Asertividad

Una aplicación web completa desarrollada en Flask para evaluar y analizar niveles de asertividad con sistema de roles (Admin, Coach, Coachee).

## 🚀 Características

- **Sistema de Roles**: Administradores, Coaches y Coachees
- **Evaluaciones de Asertividad**: Cuestionarios interactivos
- **Dashboard Personalizado**: Para cada tipo de usuario
- **Sistema de Invitaciones**: Los coaches pueden invitar coachees
- **Análisis de Resultados**: Visualización de puntuaciones y progreso
- **Autenticación Segura**: Login individual por rol

## 🛠️ Tecnologías

- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: HTML5, CSS3, JavaScript
- **Base de Datos**: SQLite
- **Deployment**: Render, Vercel

## 📁 Estructura del Proyecto

```
assessment-platform/
├── app_complete.py          # Aplicación principal
├── assessments.db           # Base de datos SQLite
├── templates/               # Plantillas HTML
├── static/                  # Archivos estáticos
├── requirements.txt         # Dependencias
├── render.yaml             # Configuración deployment
└── README.md               # Este archivo
```

## 🚀 Instalación y Uso

1. **Clonar el repositorio**
2. **Instalar dependencias**: `pip install -r requirements.txt`
3. **Ejecutar la aplicación**: `python app_complete.py`
4. **Acceder en**: `http://localhost:5000`

## 👥 Roles y Acceso

- **Admin**: `/admin-login` - Gestión de coaches y sistema
- **Coach**: `/coach-login` - Crear invitaciones y supervisar coachees
- **Coachee**: Acceso por invitación para realizar evaluaciones

## ✅ Estado del Proyecto

- ✅ Sistema de autenticación completo
- ✅ Gestión de usuarios y roles
- ✅ Sistema de invitaciones funcional
- ✅ Dashboards implementados
- ✅ Base de datos inicializada
- ✅ Listo para producción

---
*Desarrollado con Flask - Plataforma robusta y escalable*
