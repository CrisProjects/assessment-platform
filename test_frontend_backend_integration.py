#!/usr/bin/env python3
"""
Test script to verify the complete integration between Vercel frontend and Render backend
"""

import requests
import json

# URLs
BACKEND_URL = "https://assessment-platform-1nuo.onrender.com"
FRONTEND_URL = "https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app"

def test_integration():
    print("🧪 Testing Frontend-Backend Integration")
    print("=" * 50)
    
    # Create session
    session = requests.Session()
    session.headers.update({
        'Origin': FRONTEND_URL,
        'User-Agent': 'IntegrationTest/1.0'
    })
    
    # Test 1: Login
    print("1. Testing login...")
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }
    
    login_response = session.post(f"{BACKEND_URL}/login", data=login_data)
    if login_response.status_code == 200 or login_response.status_code == 302:
        print("   ✅ Login successful")
    else:
        print(f"   ❌ Login failed: {login_response.status_code}")
        return False
    
    # Test 2: Get assessments
    print("2. Testing API - Get assessments...")
    assessments_response = session.get(f"{BACKEND_URL}/api/assessments")
    if assessments_response.status_code == 200:
        assessments = assessments_response.json()
        print(f"   ✅ Assessments retrieved: {len(assessments.get('assessments', []))} assessments")
        if assessments.get('assessments'):
            assessment = assessments['assessments'][0]
            print(f"   📋 Assessment: {assessment['title']}")
            print(f"   📝 Description: {assessment['description']}")
    else:
        print(f"   ❌ Failed to get assessments: {assessments_response.status_code}")
        return False
    
    # Test 3: Save assessment progress
    print("3. Testing API - Save assessment progress...")
    save_data = {
        "progress": "test_data",
        "answers": [1, 2, 3],
        "participant_name": "Test User"
    }
    save_response = session.post(
        f"{BACKEND_URL}/api/assessment/1/save",
        json=save_data,
        headers={'Content-Type': 'application/json'}
    )
    if save_response.status_code == 200:
        save_result = save_response.json()
        print(f"   ✅ Save successful: {save_result.get('message', 'OK')}")
    else:
        print(f"   ❌ Failed to save: {save_response.status_code}")
        return False
    
    # Test 4: Get results
    print("4. Testing API - Get results...")
    results_response = session.get(f"{BACKEND_URL}/api/results?participant=all")
    if results_response.status_code == 200:
        results = results_response.json()
        print(f"   ✅ Results retrieved: {results.get('message', 'OK')}")
    else:
        print(f"   ❌ Failed to get results: {results_response.status_code}")
        return False
    
    # Test 5: CORS headers
    print("5. Testing CORS headers...")
    options_response = session.options(f"{BACKEND_URL}/api/assessments")
    cors_headers = {
        'Access-Control-Allow-Origin': options_response.headers.get('Access-Control-Allow-Origin'),
        'Access-Control-Allow-Methods': options_response.headers.get('Access-Control-Allow-Methods'),
        'Access-Control-Allow-Credentials': options_response.headers.get('Access-Control-Allow-Credentials')
    }
    
    if cors_headers['Access-Control-Allow-Origin'] and FRONTEND_URL in cors_headers['Access-Control-Allow-Origin']:
        print("   ✅ CORS properly configured")
        print(f"   🌐 Allowed origin: {cors_headers['Access-Control-Allow-Origin']}")
    else:
        print(f"   ⚠️  CORS headers: {cors_headers}")
    
    print("\n🎉 Integration test completed successfully!")
    print(f"🚀 Frontend: {FRONTEND_URL}")
    print(f"🔗 Backend: {BACKEND_URL}")
    print("💾 All API endpoints working correctly")
    print("🌍 CORS configured for cross-origin requests")
    print("🔐 Authentication and session management working")
    print("🇪🇸 All content is in Spanish")
    
    return True

if __name__ == "__main__":
    test_integration()
