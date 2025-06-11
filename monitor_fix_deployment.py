#!/usr/bin/env python3
"""
Monitor deployment and test the "Iniciar Evaluación" fix
"""
import requests
import time
from datetime import datetime

def monitor_deployment():
    print("🔄 MONITORING DEPLOYMENT FIX FOR 'INICIAR EVALUACIÓN'")
    print("=" * 60)
    print(f"Started at: {datetime.now()}")
    print()
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    # Wait for deployment
    print("⏳ Waiting for deployment to complete...")
    
    for attempt in range(12):  # 6 minutes max
        print(f"\n🔍 Attempt {attempt + 1}/12 - {datetime.now().strftime('%H:%M:%S')}")
        
        try:
            # Test health endpoint first
            health_resp = requests.get(f"{base_url}/api/health", timeout=10)
            print(f"   Health: {health_resp.status_code}")
            
            if health_resp.status_code == 200:
                print("   ✅ Backend is responding")
                break
            else:
                print("   ⏳ Still deploying...")
                
        except Exception as e:
            print(f"   ⏳ Deployment in progress: {str(e)[:50]}...")
        
        time.sleep(30)  # Wait 30 seconds
    
    print("\n🧪 TESTING THE FIX")
    print("-" * 40)
    
    session = requests.Session()
    
    try:
        # Step 1: Login as admin
        print("1. Testing admin login...")
        login_resp = session.post(f"{base_url}/api/login", json={
            'username': 'admin',
            'password': 'admin123'
        })
        
        if login_resp.status_code == 200:
            print("   ✅ Login successful")
        else:
            print(f"   ❌ Login failed: {login_resp.status_code}")
            return False
        
        # Step 2: Test demographic data registration (the fix)
        print("2. Testing demographic data registration...")
        register_resp = session.post(f"{base_url}/api/register", json={
            'name': 'Usuario Prueba',
            'email': 'prueba@test.com',
            'age': 25,
            'gender': 'masculino'
        })
        
        print(f"   Status: {register_resp.status_code}")
        
        if register_resp.status_code == 200:
            result = register_resp.json()
            print("   ✅ Demographic registration successful!")
            print(f"   User data: {result.get('user', {}).get('participant_data', {})}")
        else:
            print(f"   ❌ Registration failed: {register_resp.text}")
            return False
        
        # Step 3: Test questions endpoint
        print("3. Testing questions retrieval...")
        questions_resp = session.get(f"{base_url}/api/questions")
        
        if questions_resp.status_code == 200:
            questions_data = questions_resp.json()
            questions = questions_data.get('questions', [])
            print(f"   ✅ Questions retrieved: {len(questions)} questions")
        else:
            print(f"   ❌ Questions failed: {questions_resp.status_code}")
            return False
        
        print("\n🎉 SUCCESS! The 'Iniciar Evaluación' button should now work!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        return False

def test_complete_flow():
    """Test the complete flow that the frontend does"""
    print("\n🔄 TESTING COMPLETE FRONTEND FLOW")
    print("-" * 40)
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    session = requests.Session()
    
    try:
        # Exactly what the frontend does in startAssessment()
        
        # 1. Auto-login (line 416-420 in index.html)
        login_resp = session.post(f"{base_url}/api/login", json={
            'username': 'admin',
            'password': 'admin123'
        })
        print(f"1. Login: {login_resp.status_code} {'✅' if login_resp.status_code == 200 else '❌'}")
        
        # 2. Register demographics (line 422-428 in index.html) - THE FIX
        register_resp = session.post(f"{base_url}/api/register", json={
            'name': 'Test User',
            'email': 'test@example.com',
            'age': 30,
            'gender': 'masculino'
        })
        print(f"2. Demographics: {register_resp.status_code} {'✅' if register_resp.status_code == 200 else '❌'}")
        
        # 3. Get questions (line 430-431 in index.html)
        questions_resp = session.get(f"{base_url}/api/questions")
        print(f"3. Questions: {questions_resp.status_code} {'✅' if questions_resp.status_code == 200 else '❌'}")
        
        if all(resp.status_code == 200 for resp in [login_resp, register_resp, questions_resp]):
            print("\n🎉 ALL STEPS SUCCESSFUL!")
            print("✅ The 'Iniciar Evaluación' button is now FIXED!")
            return True
        else:
            print("\n❌ Some steps failed")
            return False
            
    except Exception as e:
        print(f"\n❌ Flow test failed: {e}")
        return False

if __name__ == "__main__":
    success1 = monitor_deployment()
    
    if success1:
        success2 = test_complete_flow()
        
        if success1 and success2:
            print("\n" + "=" * 60)
            print("🎉 PROBLEM SOLVED!")
            print("=" * 60)
            print("✅ The 'Iniciar Evaluación' button is now working correctly")
            print("✅ Users can successfully start assessments")
            print("✅ Demographic data is properly collected")
            print()
            print("📱 INSTRUCTIONS FOR USERS:")
            print("1. Go to: https://assessment-platform-1nuo.onrender.com")
            print("2. Fill in: Name, Email, Age, Gender")
            print("3. Click: 'Comenzar Evaluación' ✅ NOW WORKS!")
            print("4. Complete the 10 assertiveness questions")
            print("5. View results with detailed feedback")
        else:
            print("\n❌ PROBLEM STILL EXISTS - More debugging needed")
    else:
        print("\n❌ DEPLOYMENT FAILED - Backend issues detected")
