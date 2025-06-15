#!/usr/bin/env python3
"""
Test script to verify WSGI configuration
"""
import sys
import os

print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"Python path: {sys.path[:3]}")

try:
    print("Testing wsgi_production import...")
    from wsgi_production import application
    print("✅ WSGI application imported successfully")
    print(f"Application type: {type(application)}")
    
    # Test that the app is callable
    if hasattr(application, '__call__'):
        print("✅ Application is callable")
    else:
        print("❌ Application is not callable")
        
    # Try to get some basic info about the app
    if hasattr(application, 'url_map'):
        print(f"Routes available: {len(application.url_map._rules)}")
        for rule in list(application.url_map.iter_rules())[:5]:
            print(f"  - {rule.rule} [{rule.methods}]")
    
except Exception as e:
    print(f"❌ Error importing WSGI application: {e}")
    import traceback
    traceback.print_exc()
