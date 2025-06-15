#!/usr/bin/env python3
"""
Script para verificar que el deployment en Render está funcionando correctamente
y que todos los endpoints críticos están disponibles.
"""

import requests
import json
import time
import sys

BASE_URL = "https://assessment-platform-latest.onrender.com"

def test_endpoint(endpoint, method='GET', data=None, expected_status=200):
    """Test a specific endpoint and return the result"""
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == 'GET':
            response = requests.get(url, timeout=30)
        elif method == 'POST':
            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, json=data, headers=headers, timeout=30)
        
        print(f"✅ {method} {endpoint}: {response.status_code}")
        if response.status_code == expected_status:
            return True, response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
        else:
            return False, f"Expected {expected_status}, got {response.status_code}: {response.text}"
    except Exception as e:
        print(f"❌ {method} {endpoint}: ERROR - {str(e)}")
        return False, str(e)

def main():
    print("🔍 Testing Render deployment...")
    print(f"Base URL: {BASE_URL}")
    print("-" * 50)
    
    # Test critical endpoints
    tests = [
        # Basic app health
        ("/", "GET"),
        
        # API endpoints
        ("/api/init-db", "GET"),
        ("/api/debug-users", "GET"),
        
        # Registration endpoint
        ("/api/register", "POST", {
            "username": "test_deployment", 
            "email": "test@example.com", 
            "password": "testpass123"
        }),
        
        # Login page
        ("/login", "GET"),
        
        # Dashboard (should redirect if not authenticated)
        ("/dashboard", "GET", None, [200, 302]),
    ]
    
    results = []
    
    for test in tests:
        endpoint = test[0]
        method = test[1]
        data = test[2] if len(test) > 2 else None
        expected_status = test[3] if len(test) > 3 else 200
        
        if isinstance(expected_status, list):
            # Multiple acceptable status codes
            success = False
            result = None
            for status in expected_status:
                success, result = test_endpoint(endpoint, method, data, status)
                if success:
                    break
        else:
            success, result = test_endpoint(endpoint, method, data, expected_status)
        
        results.append((endpoint, method, success, result))
        time.sleep(1)  # Small delay between requests
    
    print("\n" + "=" * 50)
    print("SUMMARY:")
    
    successful = sum(1 for _, _, success, _ in results if success)
    total = len(results)
    
    print(f"✅ Successful: {successful}/{total}")
    print(f"❌ Failed: {total - successful}/{total}")
    
    if successful == total:
        print("\n🎉 Deployment is working correctly!")
        return 0
    else:
        print("\n⚠️ Some endpoints are not working:")
        for endpoint, method, success, result in results:
            if not success:
                print(f"  - {method} {endpoint}: {result}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
