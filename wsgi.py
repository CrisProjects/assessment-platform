#!/usr/bin/env python3
"""
WSGI entry point principal para Render
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the complete application
from app_complete import app

# This is what Render will import
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
