# RAILWAY DEPLOYMENT TRIGGER
# This file forces Railway to redeploy with latest changes

DEPLOYMENT_DATE=2025-10-04T12:55:00
COMMIT_HASH=7b35b8b
FORCE_REBUILD=true

# Latest changes include:
# - Railway debug endpoints
# - Logout fix for dual dashboards  
# - Evaluation results debugging
# - Status endpoint

# Railway should detect this change and redeploy automatically
RAILWAY_TRIGGER=ACTIVE
