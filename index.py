#!/usr/bin/env python3
"""
Entry point principal para Vercel
Alternativa a wsgi_vercel.py
"""
import os

# Set environment for Vercel
os.environ['VERCEL'] = '1'
os.environ['PRODUCTION'] = '1'
os.environ['FLASK_ENV'] = 'production'

# Import the Flask application
from app_complete import app

# Initialize database
with app.app_context():
    try:
        from app_complete import auto_initialize_database
        auto_initialize_database()
    except Exception as e:
        print(f"DB init warning: {e}")

# Export for Vercel
application = app

# For direct import
if __name__ == "__main__":
    app.run()
