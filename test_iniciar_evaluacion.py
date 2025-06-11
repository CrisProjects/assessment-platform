#!/usr/bin/env python3
"""
Test específico para el problema del botón "Iniciar Evaluación"
Simulamos exactamente lo que hace el frontend cuando el usuario hace clic
"""
import requests
import json
from datetime import datetime

def test_start_assessment_flow():
    print("🔍 TESTING BOTÓN 'INICIAR EVALUACIÓN' ISSUE")
    print("=" * 50)
    print(f"Testing at: {datetime.now()}")
    print()
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    session = requests.Session()
    
    # Simular los datos que envía el frontend
    user_data = {
        "name": "Usuario Prueba",
        "email": "prueba@test.com",
        "age": 25,
        "gender": "masculino"
    }
    
    print("📋 STEP 1: Testing login automático (como lo hace el frontend)")
    try:
        login_response = session.post(f"{base_url}/api/login", json={
            "username": "admin",
            "password": "admin123"
        })
        print(f"   Status: {login_response.status_code}")
        if login_response.status_code == 200:
            print("   ✅ Login automático successful")
            login_data = login_response.json()
            print(f"   Usuario: {login_data.get('user', {}).get('username')}")
        else:
            print(f"   ❌ Login failed: {login_response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Login error: {e}")
        return False
    
    print("\n📝 STEP 2: Testing user registration (datos demográficos)")
    try:
        register_response = session.post(f"{base_url}/api/register", json=user_data)
        print(f"   Status: {register_response.status_code}")
        if register_response.status_code == 200:
            print("   ✅ User registration successful")
            user_result = register_response.json()
            print(f"   User ID: {user_result.get('user', {}).get('id')}")
        else:
            print(f"   ❌ Registration failed: {register_response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Registration error: {e}")
        return False
    
    print("\n❓ STEP 3: Testing questions retrieval (critical step)")
    try:
        questions_response = session.get(f"{base_url}/api/questions")
        print(f"   Status: {questions_response.status_code}")
        if questions_response.status_code == 200:
            questions_data = questions_response.json()
            questions = questions_data.get('questions', questions_data)
            
            if questions and len(questions) > 0:
                print(f"   ✅ Questions retrieved: {len(questions)} questions")
                print(f"   First question: {questions[0].get('content', '')[:50]}...")
                
                # Check question format
                first_q = questions[0]
                has_options = 'options' in first_q and first_q['options']
                print(f"   Question format: ID={first_q.get('id')}, Options={bool(has_options)}")
                
                return True
            else:
                print("   ❌ No questions in response")
                print(f"   Response data: {questions_data}")
                return False
        else:
            print(f"   ❌ Questions failed: {questions_response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Questions error: {e}")
        return False

def test_frontend_javascript_simulation():
    """Test que simula exactamente el JavaScript del frontend"""
    print("\n🖥️  SIMULATING FRONTEND JAVASCRIPT BEHAVIOR")
    print("-" * 50)
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    session = requests.Session()
    
    # Exactly what the frontend does in startAssessment()
    try:
        # Step 1: Auto-login as admin (line 416-420 in index.html)
        print("1. Auto-login as admin...")
        login_resp = session.post(f"{base_url}/api/login", json={
            'username': 'admin',
            'password': 'admin123'
        })
        print(f"   Login status: {login_resp.status_code}")
        
        # Step 2: Register user demographics (line 422-428 in index.html)
        print("2. Register user demographics...")
        register_resp = session.post(f"{base_url}/api/register", json={
            'name': 'Test User',
            'email': 'test@example.com',
            'age': 30,
            'gender': 'masculino'
        })
        print(f"   Register status: {register_resp.status_code}")
        
        # Step 3: Get questions (line 430-431 in index.html)
        print("3. Get questions...")
        questions_resp = session.get(f"{base_url}/api/questions")
        print(f"   Questions status: {questions_resp.status_code}")
        
        if questions_resp.status_code == 200:
            questions_data = questions_resp.json()
            questions = questions_data.get('questions', questions_data)
            
            if questions and len(questions) > 0:
                print(f"   ✅ SUCCESS! Got {len(questions)} questions")
                
                # Test the question format that JavaScript expects
                first_q = questions[0]
                print(f"   Question structure: {list(first_q.keys())}")
                
                # Check if questions have the expected format for frontend
                expected_fields = ['id', 'content', 'options']
                missing_fields = [field for field in expected_fields if field not in first_q]
                
                if missing_fields:
                    print(f"   ⚠️  Missing fields: {missing_fields}")
                else:
                    print("   ✅ Question format is correct for frontend")
                
                return True
            else:
                print("   ❌ PROBLEM: No questions returned")
                return False
        else:
            print(f"   ❌ PROBLEM: Questions request failed with {questions_resp.status_code}")
            print(f"   Error: {questions_resp.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ CRITICAL ERROR: {e}")
        return False

if __name__ == "__main__":
    success1 = test_start_assessment_flow()
    success2 = test_frontend_javascript_simulation()
    
    print("\n🎯 DIAGNOSIS")
    print("=" * 50)
    
    if success1 and success2:
        print("✅ ALL TESTS PASSED - The assessment start flow should work")
        print("✅ If the button still doesn't work, the issue is in the frontend JavaScript")
        print("💡 Check browser console for errors")
    else:
        print("❌ TESTS FAILED - There's a backend issue preventing assessment start")
        print("🔧 The backend API is not working as expected")
    
    print(f"\n📊 Results: Test1={'✅' if success1 else '❌'}, Test2={'✅' if success2 else '❌'}")
