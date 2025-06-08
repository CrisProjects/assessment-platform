#!/usr/bin/env python3
import requests
import json

# Production backend URL
BASE_URL = "https://assessment-platform-1nuo.onrender.com"

def login_and_check_db():
    """Login to production and check database state"""
    session = requests.Session()
    
    # Login
    login_data = {
        "username": "admin",
        "password": "admin123"
    }
    
    print("Logging into production backend...")
    response = session.post(f"{BASE_URL}/api/login", json=login_data)
    
    if response.status_code == 200:
        print("✅ Login successful")
        
        # Check assessments
        print("\nChecking assessments...")
        assessments_response = session.get(f"{BASE_URL}/api/assessments")
        
        if assessments_response.status_code == 200:
            assessments_data = assessments_response.json()
            print(f"Assessment response: {assessments_data}")
            
            if 'assessments' in assessments_data:
                assessments = assessments_data['assessments']
                print(f"Found {len(assessments)} assessments:")
                
                for assessment in assessments:
                    print(f"  - {assessment['title']}: {assessment['description'][:100]}...")
                    print(f"    Created: {assessment['created_at']}")
                    print(f"    Questions count from API: {assessment['questions']}")
                    
                    # Check questions for this assessment
                    questions_response = session.get(f"{BASE_URL}/api/assessments/{assessment['id']}/questions")
                    if questions_response.status_code == 200:
                        questions_data = questions_response.json()
                        print(f"    Actual questions response: {questions_data}")
                        if 'questions' in questions_data:
                            questions = questions_data['questions']
                            print(f"    Actual questions: {len(questions)}")
                            if len(questions) > 0:
                                print(f"    First question: {questions[0]['content'][:100]}...")
                        else:
                            print(f"    No 'questions' key in response")
                    else:
                        print(f"    ❌ Error getting questions: {questions_response.status_code}")
                        print(f"    Response: {questions_response.text}")
            else:
                print(f"No 'assessments' key in response")
        else:
            print(f"❌ Error getting assessments: {assessments_response.status_code}")
            print(assessments_response.text)
    else:
        print(f"❌ Login failed: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    login_and_check_db()
