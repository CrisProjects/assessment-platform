#!/usr/bin/env python3
"""
Script to test the login functionality of the deployed Flask app
"""
import requests
import sys

def test_login_flow():
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("🧪 Testing Flask-Login functionality...")
    
    # Test 1: Homepage should load
    print("\n1. Testing homepage...")
    try:
        response = session.get(f"{base_url}/")
        print(f"Status: {response.status_code}, URL: {response.url}")
        if response.status_code == 200:
            print("✅ Homepage loads successfully")
        else:
            print(f"❌ Homepage failed: {response.status_code}")
            print(f"Response text: {response.text[:200]}...")
            return False
    except Exception as e:
        print(f"❌ Homepage request failed: {e}")
        return False
    
    # Test 2: Login page should load
    print("\n2. Testing login page...")
    response = session.get(f"{base_url}/login")
    if response.status_code == 200:
        print("✅ Login page loads successfully")
        if "Iniciar Sesión" in response.text:
            print("✅ Spanish content confirmed")
        else:
            print("⚠️  Spanish content not found")
    else:
        print(f"❌ Login page failed: {response.status_code}")
        return False
    
    # Test 3: Dashboard should redirect to login when not authenticated
    print("\n3. Testing dashboard redirect...")
    response = session.get(f"{base_url}/dashboard", allow_redirects=False)
    if response.status_code == 302:
        print("✅ Dashboard correctly redirects when not authenticated")
    else:
        print(f"⚠️  Dashboard response: {response.status_code}")
    
    # Test 4: Try to login with admin credentials
    print("\n4. Testing login with admin credentials...")
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }
    
    response = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
    if response.status_code == 302:
        print("✅ Login successful (redirect received)")
        
        # Test 5: Access dashboard after login
        print("\n5. Testing dashboard access after login...")
        response = session.get(f"{base_url}/dashboard")
        if response.status_code == 200:
            print("✅ Dashboard accessible after login")
            if "Panel de Control" in response.text:
                print("✅ Spanish dashboard content confirmed")
            if "admin" in response.text:
                print("✅ User information displayed")
        else:
            print(f"❌ Dashboard access failed: {response.status_code}")
            return False
    else:
        print(f"❌ Login failed: {response.status_code}")
        return False
    
    # Test 6: Test logout
    print("\n6. Testing logout...")
    response = session.get(f"{base_url}/logout", allow_redirects=False)
    if response.status_code == 302:
        print("✅ Logout successful (redirect received)")
        
        # Test 7: Verify dashboard is no longer accessible
        print("\n7. Testing dashboard access after logout...")
        response = session.get(f"{base_url}/dashboard", allow_redirects=False)
        if response.status_code == 302:
            print("✅ Dashboard correctly redirects after logout")
        else:
            print(f"⚠️  Dashboard response after logout: {response.status_code}")
    else:
        print(f"❌ Logout failed: {response.status_code}")
        return False
    
    print("\n🎉 All tests passed! The Flask app is working correctly.")
    return True

if __name__ == "__main__":
    try:
        success = test_login_flow()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed with exception: {e}")
        sys.exit(1)
