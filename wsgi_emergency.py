#!/usr/bin/env python3
"""
Alternative WSGI configuration to force Render refresh
"""
import os
import sys
from datetime import datetime

# Force refresh marker
DEPLOYMENT_VERSION = "emergency-rebuild-" + datetime.utcnow().strftime("%Y%m%d_%H%M%S")

print(f"🚀 STARTING EMERGENCY DEPLOYMENT: {DEPLOYMENT_VERSION}")

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import the complete application with error handling
try:
    from app_complete import app
    print("✅ Successfully imported app_complete")
    
    # Verify routes are loaded
    route_count = len(list(app.url_map.iter_rules()))
    print(f"✅ Loaded {route_count} routes")
    
    # Check for our new endpoints
    new_endpoints = ['/api/health', '/api/questions', '/api/register', '/api/submit']
    routes = [rule.rule for rule in app.url_map.iter_rules()]
    
    for endpoint in new_endpoints:
        if endpoint in routes:
            print(f"✅ Found endpoint: {endpoint}")
        else:
            print(f"❌ Missing endpoint: {endpoint}")
    
except Exception as e:
    print(f"❌ Failed to import app_complete: {e}")
    import traceback
    traceback.print_exc()
    
    # Fallback to a minimal app
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    def emergency():
        return f"EMERGENCY MODE - {DEPLOYMENT_VERSION}"
    
    @app.route('/api/emergency')
    def api_emergency():
        return jsonify({'status': 'emergency', 'version': DEPLOYMENT_VERSION})

# This is what Render will import
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    print(f"🚀 Starting application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
