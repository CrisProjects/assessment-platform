#!/usr/bin/env python3
"""
Force Render Update Script
This script creates a unique deployment marker to force Render to rebuild with latest code
"""
import time
import json
import os
from datetime import datetime

def create_deployment_marker():
    """Create a unique deployment marker file"""
    timestamp = int(time.time())
    deployment_id = f"deploy_{timestamp}"
    
    marker_data = {
        "deployment_id": deployment_id,
        "timestamp": timestamp,
        "datetime": datetime.now().isoformat(),
        "action": "force_render_rebuild",
        "endpoints_added": [
            "/api/register",
            "/api/questions", 
            "/api/submit",
            "/api/health",
            "/api/deployment-test"
        ],
        "procfile": "web: gunicorn wsgi_complete:application",
        "wsgi_module": "wsgi_complete.py"
    }
    
    # Create deployment marker
    with open('.render_deploy_marker', 'w') as f:
        json.dump(marker_data, f, indent=2)
    
    print(f"Created deployment marker: {deployment_id}")
    return deployment_id

def update_procfile_with_marker():
    """Add deployment marker to Procfile"""
    deployment_id = create_deployment_marker()
    
    # Read current Procfile
    with open('Procfile', 'r') as f:
        content = f.read().strip()
    
    # Add deployment marker as comment
    new_content = f"""{content}
# Deployment ID: {deployment_id}
# Force rebuild timestamp: {int(time.time())}"""
    
    with open('Procfile', 'w') as f:
        f.write(new_content)
    
    print(f"Updated Procfile with deployment marker: {deployment_id}")
    return deployment_id

if __name__ == "__main__":
    deployment_id = update_procfile_with_marker()
    print(f"\n=== RENDER FORCE UPDATE ===")
    print(f"Deployment ID: {deployment_id}")
    print(f"Next steps:")
    print(f"1. git add .")
    print(f"2. git commit -m 'Force Render rebuild - {deployment_id}'")
    print(f"3. git push origin main")
    print(f"4. Monitor deployment at Render dashboard")
