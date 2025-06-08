import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("[RENDER DEBUG] wsgi_root.py starting...")
print(f"[RENDER DEBUG] Python version: {sys.version}")
print(f"[RENDER DEBUG] Current working directory: {os.getcwd()}")
print(f"[RENDER DEBUG] Files in current directory: {os.listdir('.')}")

try:
    from app_root import app
    print("[RENDER DEBUG] app_root imported successfully")
    print(f"[RENDER DEBUG] Flask app: {app}")
    print(f"[RENDER DEBUG] App routes: {[rule.rule for rule in app.url_map.iter_rules()]}")
except ImportError as e:
    print(f"[RENDER ERROR] Could not import app_root: {e}")
    print(f"[RENDER ERROR] Available files: {os.listdir('.')}")
    raise

# Ensure app runs on the correct port
port = int(os.environ.get('PORT', 8000))
print(f"[RENDER DEBUG] Using port: {port}")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=port)
