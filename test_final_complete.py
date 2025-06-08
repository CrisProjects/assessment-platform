#!/usr/bin/env python3
"""
Final comprehensive test of the login flow with the latest deployment URLs
"""

import requests
import json

def test_final_deployment():
    """Test the complete flow with latest deployment URLs"""
    
    print("🎯 TESTING FINAL DEPLOYMENT AUTHENTICATION")
    print("=" * 55)
    
    # Latest deployment URLs
    frontend_url = "https://assessment-platform-g18jyp9wv-cris-projects-92f3df55.vercel.app"
    backend_url = "https://assessment-platform-1nuo.onrender.com"
    
    print(f"🌐 Frontend: {frontend_url}")
    print(f"🔧 Backend:  {backend_url}")
    print()
    
    # Test 1: Check backend health
    print("1️⃣ Backend Health Check...")
    try:
        response = requests.get(f"{backend_url}/api/test/status", timeout=10)
        if response.status_code == 200:
            print("   ✅ Backend is responding")
        else:
            print(f"   ❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Backend health check error: {e}")
        return False
    
    # Test 2: CORS Preflight from new frontend
    print("2️⃣ CORS Preflight Test...")
    try:
        response = requests.options(
            f"{backend_url}/api/login",
            headers={
                'Origin': frontend_url,
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'content-type'
            },
            timeout=10
        )
        
        print(f"   Status: {response.status_code}")
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        print(f"   CORS Origin: {cors_origin}")
        
        if response.status_code in [200, 204]:
            print("   ✅ CORS Preflight successful")
            if cors_origin == frontend_url:
                print("   ✅ CORS Origin matches frontend URL")
            else:
                print("   ⚠️  CORS Origin doesn't match frontend URL")
        else:
            print("   ❌ CORS Preflight failed")
            return False
            
    except Exception as e:
        print(f"   ❌ CORS Preflight error: {e}")
        return False
    
    # Test 3: Login with credentials
    print("3️⃣ Login Authentication Test...")
    try:
        response = requests.post(
            f"{backend_url}/api/login",
            headers={
                'Content-Type': 'application/json',
                'Origin': frontend_url
            },
            json={
                'username': 'admin',
                'password': 'admin123'
            },
            timeout=10
        )
        
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
            
            if data.get('success'):
                print("   ✅ Login authentication successful")
                user = data.get('user', {})
                print(f"   👤 User: {user.get('username')} (Admin: {user.get('is_admin')})")
                return True
            else:
                print(f"   ❌ Login failed: {data.get('error')}")
                return False
        else:
            print(f"   ❌ Login request failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Login error: {e}")
        return False

if __name__ == "__main__":
    print()
    success = test_final_deployment()
    print()
    print("=" * 55)
    if success:
        print("🎉 SUCCESS! Authentication is working correctly!")
        print("✅ You can now log in to the frontend with:")
        print("   Username: admin")
        print("   Password: admin123")
        print()
        print(f"🔗 Login at: https://assessment-platform-g18jyp9wv-cris-projects-92f3df55.vercel.app")
    else:
        print("❌ FAILED! There are still issues with the authentication.")
    print("=" * 55)
