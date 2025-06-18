#!/usr/bin/env python3
"""
WSGI de diagnóstico para Render
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app_diagnostic import diagnostic_app
    application = diagnostic_app
except ImportError as e:
    print(f"ERROR importing diagnostic app: {e}")
    # Fallback app
    from flask import Flask
    application = Flask(__name__)
    
    @application.route('/')
    def fallback():
        return {"status": "FALLBACK_APP", "error": "Could not import diagnostic app"}

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    application.run(host='0.0.0.0', port=port)
