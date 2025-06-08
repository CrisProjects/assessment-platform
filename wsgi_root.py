import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("[RENDER DEBUG] wsgi_root.py starting...")

try:
    from app_root import app
    print("[RENDER DEBUG] app_root imported successfully")
except ImportError as e:
    print(f"[RENDER ERROR] Could not import app_root: {e}")
    raise

if __name__ == "__main__":
    app.run()
