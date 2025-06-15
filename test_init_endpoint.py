#!/usr/bin/env python3
"""
Test script to debug the init-db endpoint issue
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app_complete import app, init_database

def test_init_database():
    """Test the init_database function directly"""
    print("Testing init_database() function...")
    
    with app.app_context():
        try:
            result = init_database()
            print(f"init_database() returned: {result}")
            print(f"Type: {type(result)}")
            print(f"Bool conversion: {bool(result)}")
            
            # Test JSON serialization
            import json
            test_data = {
                'result': result,
                'bool_result': bool(result),
                'test': 'success'
            }
            
            json_str = json.dumps(test_data)
            print(f"JSON serialization test: SUCCESS")
            print(f"JSON: {json_str}")
            
        except Exception as e:
            print(f"Error: {e}")
            print(f"Error type: {type(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_init_database()
