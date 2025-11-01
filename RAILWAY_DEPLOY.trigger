# RAILWAY DEPLOYMENT TRIGGER
# This file forces Railway to redeploy with latest changes

DEPLOYMENT_DATE=2025-10-18T11:45:00
COMMIT_HASH=d8217e5
FORCE_REBUILD=true

# Latest changes include:
# - Funcionalidad completa de edición de coachees (botón editar funcional)
# - Modal de edición responsivo con validaciones
# - Endpoint PUT /api/coach/update-coachee/<id>
# - Mejoras en estilos de modal de video coachee dashboard  
# - Evaluation results debugging
# - Status endpoint

# Railway should detect this change and redeploy automatically
RAILWAY_TRIGGER=ACTIVE
# Force deploy - Fri Oct 31 21:39:37 -03 2025
