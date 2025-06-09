#!/usr/bin/env python3
"""
Monitor the final deployment fix
"""
import requests
import time
import datetime

def test_endpoint(url):
    try:
        response = requests.get(url, timeout=10)
        return response.status_code, response.text[:100] if response.text else ""
    except Exception as e:
        return None, str(e)

def main():
    print("🔄 MONITORING FINAL DEPLOYMENT FIX")
    print("=" * 50)
    print(f"Started at: {datetime.datetime.now()}")
    print()
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    # Key endpoints to test
    endpoints = [
        ("/api/health", "Health check - should return 200 with JSON"),
        ("/api/deployment-test", "Deployment test - should return JSON"),
        ("/api/questions", "Questions endpoint - should return 401/403 (needs auth)"),
        ("/", "Frontend - should return 200 with HTML")
    ]
    
    attempt = 0
    success = False
    
    while attempt < 10 and not success:  # 5 minutes max
        attempt += 1
        print(f"\n⏰ Attempt {attempt} - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print("-" * 40)
        
        all_working = True
        
        for endpoint, description in endpoints:
            url = f"{base_url}{endpoint}"
            status, content = test_endpoint(url)
            
            if status is None:
                print(f"❌ {endpoint}: ERROR - {content}")
                all_working = False
            elif endpoint == "/api/health" and status == 200:
                print(f"✅ {endpoint}: {status} - SUCCESS! API is working")
            elif endpoint == "/api/deployment-test" and status == 200:
                print(f"✅ {endpoint}: {status} - Deployment test working")
            elif endpoint == "/api/questions" and status in [401, 403]:
                print(f"✅ {endpoint}: {status} - Requires auth (as expected)")
            elif endpoint == "/" and status == 200:
                print(f"✅ {endpoint}: {status} - Frontend working")
            else:
                print(f"⏳ {endpoint}: {status} - Still deploying...")
                all_working = False
        
        if endpoint == "/api/health" and status == 200:
            print(f"\n🎉 DEPLOYMENT SUCCESSFUL!")
            print(f"All new API endpoints are now working!")
            success = True
            break
            
        if attempt < 10:
            print("Waiting 30 seconds...")
            time.sleep(30)
    
    if not success:
        print(f"\n⚠️ Still deploying after {attempt} attempts")

if __name__ == "__main__":
    main()
