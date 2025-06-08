#!/usr/bin/env python3
"""
Test final login functionality between new Vercel frontend and Render backend
"""

import requests
import json

def test_final_login():
    """Test the complete login flow with the new deployment URLs"""
    
    print("🧪 Testing Final Login Flow")
    print("=" * 50)
    
    # New deployment URLs
    frontend_url = "https://assessment-platform-g18jyp9wv-cris-projects-92f3df55.vercel.app"
    backend_url = "https://assessment-platform-1nuo.onrender.com"
    
    print(f"Frontend URL: {frontend_url}")
    print(f"Backend URL: {backend_url}")
    print()
    
    # Test 1: CORS Preflight
    print("1️⃣ Testing CORS Preflight...")
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
        print(f"   CORS Origin: {response.headers.get('Access-Control-Allow-Origin')}")
        
        if response.status_code in [200, 204]:
            print("   ✅ CORS Preflight successful")
        else:
            print("   ❌ CORS Preflight failed")
            return False
            
    except Exception as e:
        print(f"   ❌ CORS Preflight error: {e}")
        return False
    
    print()
    
    # Test 2: Actual Login
    print("2️⃣ Testing Login API...")
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
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("   ✅ Login successful!")
                print(f"   User: {data.get('user', {}).get('username')}")
                return True
            else:
                print(f"   ❌ Login failed: {data.get('error')}")
                return False
        else:
            print(f"   ❌ Login request failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Login error: {e}")
        return False

if __name__ == "__main__":
    success = test_final_login()
    print()
    if success:
        print("🎉 All tests passed! Authentication should work in the frontend.")
    else:
        print("❌ Tests failed. There may still be issues.")
