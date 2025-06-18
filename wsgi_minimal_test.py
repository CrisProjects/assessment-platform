#!/usr/bin/env python3
"""
WSGI para app mínima de prueba
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("[MINIMAL DEBUG] wsgi_minimal_test.py starting...")

try:
    from app_minimal_test import app
    print("[MINIMAL DEBUG] app_minimal_test imported successfully")
    print(f"[MINIMAL DEBUG] Flask app: {app}")
except ImportError as e:
    print(f"[MINIMAL ERROR] Could not import app_minimal_test: {e}")
    raise

# This is what Render will import
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
