#!/usr/bin/env python3
"""
Real-time deployment tracker for Render backend
"""
import requests
import time
import datetime

def check_endpoint(url):
    try:
        response = requests.get(url, timeout=10)
        return response.status_code, response.text[:100] if response.text else ""
    except Exception as e:
        return None, str(e)

def main():
    print("🔄 TRACKING RENDER DEPLOYMENT")
    print("=" * 50)
    print(f"Started at: {datetime.datetime.now()}")
    print()
    
    base_url = "https://assessment-platform-1nuo.onrender.com"
    
    # Endpoints to check
    endpoints = [
        ("/api/health", "NEW - Should return 200"),
        ("/api/questions", "NEW - Should return 200"),
        ("/api/login", "OLD - Should return 405"),
        ("/", "Frontend - Should return 200")
    ]
    
    attempt = 0
    deployment_detected = False
    
    while attempt < 30:  # Check for 15 minutes
        attempt += 1
        print(f"\n⏰ Attempt {attempt} - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print("-" * 40)
        
        all_good = True
        
        for endpoint, description in endpoints:
            url = f"{base_url}{endpoint}"
            status, content = check_endpoint(url)
            
            if status is None:
                print(f"❌ {endpoint}: ERROR - {content}")
                all_good = False
            elif endpoint == "/api/health" and status == 200:
                if not deployment_detected:
                    print(f"🎉 DEPLOYMENT SUCCESSFUL! New endpoints are live!")
                    deployment_detected = True
                print(f"✅ {endpoint}: {status} - {description}")
            elif endpoint == "/api/health" and status == 404:
                print(f"⏳ {endpoint}: {status} - Still deploying...")
                all_good = False
            else:
                print(f"✅ {endpoint}: {status} - {description}")
        
        if deployment_detected and all_good:
            print(f"\n🚀 DEPLOYMENT COMPLETE!")
            print(f"All endpoints are working correctly.")
            break
            
        if attempt < 30:
            print("Waiting 30 seconds...")
            time.sleep(30)
    
    if not deployment_detected:
        print(f"\n⚠️ Deployment not detected after {attempt} attempts")
        print("Manual investigation may be required.")

if __name__ == "__main__":
    main()
