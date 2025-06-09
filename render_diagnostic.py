#!/usr/bin/env python3
"""
Comprehensive diagnostic for Render deployment issues
"""
import requests
import time
import json
from datetime import datetime

def test_endpoint(url, expected_status=None):
    """Test an endpoint and return detailed information"""
    try:
        response = requests.get(url, timeout=10)
        return {
            'url': url,
            'status': response.status_code,
            'success': True,
            'headers': dict(response.headers),
            'content_length': len(response.text),
            'content_preview': response.text[:200] if response.text else ""
        }
    except Exception as e:
        return {
            'url': url,
            'status': None,
            'success': False,
            'error': str(e)
        }

def main():
    print("🔍 COMPREHENSIVE RENDER DEPLOYMENT DIAGNOSTIC")
    print("=" * 60)
    print(f"Timestamp: {datetime.now()}")
    print()
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    # Test all endpoints
    endpoints = [
        # Frontend
        "/",
        "/favicon.ico",
        
        # Old API endpoints (should work)
        "/api/login",
        "/api/logout",
        "/api/assessments",
        "/api/save_assessment",
        
        # New API endpoints (currently failing)
        "/api/health",
        "/api/questions",
        "/api/register", 
        "/api/submit",
        "/api/deployment-test"
    ]
    
    results = []
    
    print("🌐 TESTING ALL ENDPOINTS:")
    print("-" * 40)
    
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        result = test_endpoint(url)
        results.append(result)
        
        status_icon = "✅" if result['success'] else "❌"
        status_code = result.get('status', 'ERROR')
        
        print(f"{status_icon} {endpoint:<25} | {status_code}")
        
        if not result['success']:
            print(f"   Error: {result['error']}")
        elif result['status'] in [200, 405, 400]:  # Expected statuses
            print(f"   Content preview: {result['content_preview'][:50]}...")
    
    print("\n📊 ANALYSIS:")
    print("-" * 40)
    
    working_endpoints = [r for r in results if r['success'] and r['status'] in [200, 405, 400]]
    failing_endpoints = [r for r in results if not r['success'] or r['status'] == 404]
    
    print(f"✅ Working endpoints: {len(working_endpoints)}")
    print(f"❌ Failing endpoints: {len(failing_endpoints)}")
    
    if failing_endpoints:
        print("\n🚨 FAILING ENDPOINTS:")
        for result in failing_endpoints:
            endpoint = result['url'].replace(base_url, '')
            print(f"   {endpoint} - Status: {result.get('status', 'ERROR')}")
    
    # Check if this looks like a deployment issue
    old_api_working = any(r['url'].endswith('/api/login') and r['status'] in [405, 400] for r in results)
    new_api_failing = any(r['url'].endswith('/api/health') and r['status'] == 404 for r in results)
    
    if old_api_working and new_api_failing:
        print("\n🎯 DIAGNOSIS:")
        print("   This appears to be a deployment synchronization issue.")
        print("   - Old endpoints are working (405/400 status)")
        print("   - New endpoints are missing (404 status)")
        print("   - Render may be serving cached/old application code")
        
        print("\n💡 RECOMMENDED ACTIONS:")
        print("   1. Check Render dashboard for build logs")
        print("   2. Manually trigger rebuild in Render dashboard")
        print("   3. Consider creating new Render service")
        print("   4. Check for any build script issues")

if __name__ == "__main__":
    main()
