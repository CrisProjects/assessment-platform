import sys
import os

# Agregar el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("[RENDER DEBUG] wsgi_simple.py iniciando...")

try:
    from app_simple import app
    print("[RENDER DEBUG] app_simple importado exitosamente")
except ImportError as e:
    print(f"[RENDER ERROR] No se pudo importar app_simple: {e}")
    # Fallback al app original
    from app import app
    print("[RENDER DEBUG] Usando app original como fallback")

if __name__ == "__main__":
    app.run()
