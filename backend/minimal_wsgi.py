import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("[RENDER DEBUG] minimal_wsgi.py starting...")

try:
    from test_minimal import app
    print("[RENDER DEBUG] test_minimal imported successfully")
except ImportError as e:
    print(f"[RENDER ERROR] Could not import test_minimal: {e}")
    # Fallback to original app
    try:
        from app_simple import app
        print("[RENDER DEBUG] Using app_simple as fallback")
    except ImportError as e2:
        print(f"[RENDER ERROR] Could not import app_simple either: {e2}")
        raise

if __name__ == "__main__":
    app.run()
