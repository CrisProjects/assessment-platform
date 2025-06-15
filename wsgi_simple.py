#!/usr/bin/env python3
"""
Simplified WSGI entry point for debugging
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def application(environ, start_response):
    """Simple WSGI application for testing"""
    status = '200 OK'
    headers = [('Content-type', 'text/plain')]
    start_response(status, headers)
    return [b'Simple WSGI app is working on Render!']

# Also expose the Flask app as backup
try:
    from app_complete import app as flask_app
    # Use Flask app if available
    application = flask_app.wsgi_app
except Exception as e:
    print(f"Flask app not available, using simple WSGI: {e}")
    # Keep the simple WSGI function above
