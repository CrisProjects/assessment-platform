#!/usr/bin/env python3
"""
Debug script to verify all routes are properly registered
"""
from app_complete import app

def list_all_routes():
    print("=" * 60)
    print("ALL REGISTERED ROUTES IN app_complete.py")
    print("=" * 60)
    
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'rule': rule.rule,
            'methods': sorted(rule.methods - {'HEAD', 'OPTIONS'})
        })
    
    # Sort by route path
    routes.sort(key=lambda x: x['rule'])
    
    for route in routes:
        methods_str = ', '.join(route['methods'])
        print(f"{route['rule']:<25} | {methods_str:<15} | {route['endpoint']}")
    
    print("\n" + "=" * 60)
    print(f"Total routes: {len(routes)}")
    
    # Check specifically for our new API endpoints
    print("\n🔍 CHECKING NEW API ENDPOINTS:")
    new_endpoints = ['/api/health', '/api/register', '/api/questions', '/api/submit']
    
    for endpoint in new_endpoints:
        found = any(route['rule'] == endpoint for route in routes)
        status = "✅ FOUND" if found else "❌ MISSING"
        print(f"{endpoint:<20} | {status}")

if __name__ == "__main__":
    list_all_routes()
