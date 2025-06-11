#!/usr/bin/env python3
"""
FINAL STATUS REPORT - Assessment Platform Deployment
Complete verification of all endpoints and functionality
"""
import requests
import json
from datetime import datetime

def comprehensive_platform_test():
    print("🎯 COMPREHENSIVE PLATFORM STATUS REPORT")
    print("=" * 60)
    print(f"Report generated: {datetime.now()}")
    print()
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    vercel_url = "https://assessment-platform-cris-projects-92f3df55.vercel.app"
    
    # Test all endpoints
    session = requests.Session()
    
    # Results tracking
    results = {
        'frontend': {},
        'backend': {},
        'auth': {},
        'assessment': {},
        'overall': True
    }
    
    print("🌐 TESTING FRONTEND ACCESSIBILITY")
    print("-" * 40)
    
    # Test main frontend
    try:
        response = requests.get(base_url, timeout=10)
        status = "✅ WORKING" if response.status_code == 200 else f"❌ ERROR ({response.status_code})"
        print(f"Main App (Render):  {status}")
        results['frontend']['render'] = response.status_code == 200
    except Exception as e:
        print(f"Main App (Render):  ❌ ERROR - {e}")
        results['frontend']['render'] = False
    
    # Test Vercel frontend
    try:
        response = requests.get(vercel_url, timeout=10)
        status = "✅ WORKING" if response.status_code == 200 else f"❌ ERROR ({response.status_code})"
        print(f"Alt Frontend (Vercel): {status}")
        results['frontend']['vercel'] = response.status_code == 200
    except Exception as e:
        print(f"Alt Frontend (Vercel): ❌ ERROR - {e}")
        results['frontend']['vercel'] = False
    
    print("\n🔧 TESTING BACKEND API ENDPOINTS")
    print("-" * 40)
    
    # Test health endpoint
    try:
        response = session.get(f"{base_url}/api/health")
        status = "✅ HEALTHY" if response.status_code == 200 else f"❌ UNHEALTHY ({response.status_code})"
        print(f"Health Check:       {status}")
        results['backend']['health'] = response.status_code == 200
        if response.status_code == 200:
            health_data = response.json()
            print(f"                    Database: {health_data.get('database', 'unknown')}")
    except Exception as e:
        print(f"Health Check:       ❌ ERROR - {e}")
        results['backend']['health'] = False
    
    # Test deployment test endpoint
    try:
        response = session.get(f"{base_url}/api/deployment-test")
        status = "✅ WORKING" if response.status_code == 200 else f"❌ ERROR ({response.status_code})"
        print(f"Deployment Test:    {status}")
        results['backend']['deployment'] = response.status_code == 200
    except Exception as e:
        print(f"Deployment Test:    ❌ ERROR - {e}")
        results['backend']['deployment'] = False
    
    print("\n🔐 TESTING AUTHENTICATION")
    print("-" * 40)
    
    # Test login
    login_data = {"username": "admin", "password": "admin123"}
    try:
        response = session.post(f"{base_url}/api/login", json=login_data)
        if response.status_code == 200:
            print("Login Endpoint:     ✅ WORKING")
            login_result = response.json()
            user_info = login_result.get('user', {})
            print(f"                    User: {user_info.get('username')}")
            print(f"                    Admin: {user_info.get('is_admin')}")
            results['auth']['login'] = True
        else:
            print(f"Login Endpoint:     ❌ ERROR ({response.status_code})")
            results['auth']['login'] = False
    except Exception as e:
        print(f"Login Endpoint:     ❌ ERROR - {e}")
        results['auth']['login'] = False
    
    print("\n❓ TESTING ASSESSMENT FUNCTIONALITY")
    print("-" * 40)
    
    # Test questions endpoint (requires auth)
    try:
        response = session.get(f"{base_url}/api/questions")
        if response.status_code == 200:
            questions_data = response.json()
            questions = questions_data.get('questions', [])
            print(f"Questions Endpoint: ✅ WORKING ({len(questions)} questions)")
            results['assessment']['questions'] = True
            
            # Test assessment submission
            if questions:
                responses = []
                for i, question in enumerate(questions[:3]):  # Test with 3 questions
                    responses.append({
                        "question_id": question['id'],
                        "selected_option": i % 2,  # Alternate between first two options
                        "option_text": f"Test response {i}"
                    })
                
                submission_data = {
                    "assessment_id": 1,
                    "responses": responses
                }
                
                # Test submit endpoint
                try:
                    response = session.post(f"{base_url}/api/submit", json=submission_data)
                    if response.status_code == 200:
                        result = response.json()
                        print(f"Submit Endpoint:    ✅ WORKING")
                        print(f"                    Score: {result.get('score')}%")
                        print(f"                    Level: {result.get('score_level')}")
                        results['assessment']['submit'] = True
                    else:
                        print(f"Submit Endpoint:    ❌ ERROR ({response.status_code})")
                        results['assessment']['submit'] = False
                except Exception as e:
                    print(f"Submit Endpoint:    ❌ ERROR - {e}")
                    results['assessment']['submit'] = False
            else:
                print("Submit Endpoint:    ⚠️  NO QUESTIONS TO TEST")
                results['assessment']['submit'] = False
        else:
            print(f"Questions Endpoint: ❌ ERROR ({response.status_code})")
            results['assessment']['questions'] = False
            results['assessment']['submit'] = False
    except Exception as e:
        print(f"Questions Endpoint: ❌ ERROR - {e}")
        results['assessment']['questions'] = False
        results['assessment']['submit'] = False
    
    # Calculate overall status
    all_tests = [
        results['frontend']['render'],
        results['backend']['health'],
        results['auth']['login'],
        results['assessment']['questions'],
        results['assessment']['submit']
    ]
    
    working_tests = sum(all_tests)
    total_tests = len(all_tests)
    success_rate = (working_tests / total_tests) * 100
    
    print("\n🎯 FINAL STATUS SUMMARY")
    print("=" * 60)
    print(f"Success Rate: {working_tests}/{total_tests} ({success_rate:.1f}%)")
    print()
    
    if success_rate >= 90:
        status_emoji = "🟢"
        status_text = "FULLY OPERATIONAL"
        status_description = "All critical systems are working perfectly!"
    elif success_rate >= 70:
        status_emoji = "🟡"
        status_text = "MOSTLY OPERATIONAL"
        status_description = "Core functionality working with minor issues."
    else:
        status_emoji = "🔴"
        status_text = "NEEDS ATTENTION"
        status_description = "Multiple systems require debugging."
    
    print(f"{status_emoji} PLATFORM STATUS: {status_text}")
    print(f"   {status_description}")
    print()
    
    print("📋 DETAILED RESULTS:")
    print(f"   Frontend (Render):     {'✅' if results['frontend']['render'] else '❌'}")
    print(f"   Frontend (Vercel):     {'✅' if results['frontend']['vercel'] else '❌'}")
    print(f"   Backend Health:        {'✅' if results['backend']['health'] else '❌'}")
    print(f"   Authentication:        {'✅' if results['auth']['login'] else '❌'}")
    print(f"   Questions Retrieval:   {'✅' if results['assessment']['questions'] else '❌'}")
    print(f"   Assessment Submission: {'✅' if results['assessment']['submit'] else '❌'}")
    print()
    
    print("🔗 PLATFORM URLS:")
    print(f"   Main Application: {base_url}")
    print(f"   Alternative Frontend: {vercel_url}")
    print(f"   API Health: {base_url}/api/health")
    print()
    
    print("👤 DEFAULT CREDENTIALS:")
    print("   Username: admin")
    print("   Password: admin123")
    print()
    
    if success_rate >= 90:
        print("🎉 DEPLOYMENT COMPLETE - PLATFORM READY FOR USE!")
    else:
        print("⚠️  DEPLOYMENT NEEDS ATTENTION - See failed tests above")
    
    return success_rate >= 90

if __name__ == "__main__":
    success = comprehensive_platform_test()
    exit(0 if success else 1)
