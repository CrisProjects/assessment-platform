#!/usr/bin/env python3
"""
Prueba local del frontend estático antes de desplegar a Vercel
"""
import http.server
import socketserver
import webbrowser
import threading
import time

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve index.html for all routes (SPA behavior)
        if not self.path.startswith('/api') and not '.' in self.path.split('/')[-1]:
            self.path = '/index.html'
        return super().do_GET()

def start_local_server():
    """Start a local server to test the frontend"""
    PORT = 8080
    
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        print(f"🌐 Servidor local iniciado en http://localhost:{PORT}")
        print("📱 Frontend conectándose al backend de producción:")
        print("   Backend: https://assessment-platform-1nuo.onrender.com")
        print("\n🧪 Prueba lo siguiente:")
        print("   1. Login con admin/admin123")
        print("   2. Completa la evaluación")
        print("   3. Verifica que los resultados se muestren correctamente")
        print("\n⏹️  Presiona Ctrl+C para detener el servidor")
        
        # Abrir el navegador automáticamente
        threading.Timer(1, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Servidor detenido")

if __name__ == "__main__":
    start_local_server()
