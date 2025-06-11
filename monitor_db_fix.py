#!/usr/bin/env python3
"""
Monitor the database fix deployment and initialize production database
"""
import requests
import time
import json

def test_deployment():
    """Test if the new deployment is working"""
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    try:
        # Test health endpoint
        health_response = requests.get(f"{base_url}/api/health", timeout=10)
        if health_response.status_code != 200:
            return False, "Health check failed"
        
        # Test login
        login_response = requests.post(
            f"{base_url}/api/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10
        )
        
        if login_response.status_code != 200:
            return False, "Login failed"
        
        # Get session cookie
        session_cookie = login_response.cookies.get('session')
        if not session_cookie:
            return False, "No session cookie received"
        
        # Test questions endpoint
        questions_response = requests.get(
            f"{base_url}/api/questions",
            cookies={'session': session_cookie},
            timeout=10
        )
        
        if questions_response.status_code != 200:
            return False, f"Questions endpoint failed: {questions_response.status_code}"
        
        questions_data = questions_response.json()
        if len(questions_data.get('questions', [])) != 10:
            return False, f"Expected 10 questions, got {len(questions_data.get('questions', []))}"
        
        return True, "All tests passed"
        
    except Exception as e:
        return False, f"Error: {str(e)}"

def initialize_production_db():
    """Initialize the production database"""
    print("🔧 Initializing production database...")
    
    try:
        response = requests.get("https://assessment-platform-1nuo.onrender.com/api/init-db", timeout=30)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Database initialized: {data}")
            return True
        else:
            print(f"❌ Database initialization failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        return False

def main():
    print("🚀 MONITORING DATABASE FIX DEPLOYMENT")
    print("=" * 50)
    print("Waiting for Render to complete deployment...")
    print("This typically takes 3-5 minutes.")
    print()
    
    attempt = 0
    max_attempts = 15  # 7.5 minutes
    
    while attempt < max_attempts:
        attempt += 1
        print(f"⏰ Attempt {attempt}/{max_attempts} - {time.strftime('%H:%M:%S')}")
        
        success, message = test_deployment()
        
        if success:
            print("🎉 DEPLOYMENT SUCCESSFUL!")
            print("✅ Health check: Working")
            print("✅ Login: Working")
            print("✅ Questions API: Working")
            print("✅ Database: 10 questions loaded")
            print()
            print("🌐 Platform ready at: https://assessment-platform-1nuo.onrender.com")
            print("🔐 Login credentials: admin / admin123")
            return True
        else:
            print(f"⏳ Not ready yet: {message}")
            if "Database" in message:
                print("   💡 Attempting database initialization...")
                initialize_production_db()
        
        if attempt < max_attempts:
            print("   Waiting 30 seconds...")
            time.sleep(30)
        print()
    
    print("⚠️ Deployment monitoring timeout reached")
    print("The deployment may still be in progress.")
    print("Try manually at: https://assessment-platform-1nuo.onrender.com")
    return False

if __name__ == "__main__":
    main()
