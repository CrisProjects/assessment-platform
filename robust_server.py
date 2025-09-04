#!/usr/bin/env python3
"""
🚀 SERVIDOR ROBUSTO PARA ASSESSMENT PLATFORM
===============================================
Script mejorado con reinicio automático y mejor estabilidad
"""

import os
import sys
import time
import signal
import subprocess
from datetime import datetime

# Configuración
PORT = 5002
MAX_RESTARTS = 10
RESTART_DELAY = 2  # segundos entre reinicios

class RobustServer:
    def __init__(self):
        self.restart_count = 0
        self.server_process = None
        self.running = True
        
    def signal_handler(self, signum, frame):
        """Manejo de señales para cierre limpio"""
        print(f"\n🛑 Señal {signum} recibida. Cerrando servidor...")
        self.running = False
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
        print("✅ Servidor cerrado correctamente")
        sys.exit(0)
    
    def check_dependencies(self):
        """Verificar que los archivos necesarios existen"""
        required_files = ['app.py', 'start_server.py']
        for file in required_files:
            if not os.path.exists(file):
                print(f"❌ ERROR: Archivo {file} no encontrado")
                return False
        return True
    
    def start_server(self):
        """Iniciar el servidor Flask"""
        try:
            print(f"🚀 Iniciando servidor Flask (intento {self.restart_count + 1})...")
            print(f"📍 Puerto: {PORT}")
            print(f"🕒 Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Usar start_server.py para mayor estabilidad
            self.server_process = subprocess.Popen(
                [sys.executable, 'start_server.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            return True
            
        except Exception as e:
            print(f"❌ Error iniciando servidor: {e}")
            return False
    
    def monitor_server(self):
        """Monitorear el servidor y capturar salida"""
        try:
            while self.running and self.server_process:
                # Leer salida del servidor
                output = self.server_process.stdout.readline()
                if output:
                    print(output.strip())
                
                # Verificar si el proceso sigue vivo
                if self.server_process.poll() is not None:
                    print(f"⚠️ El servidor se detuvo con código: {self.server_process.returncode}")
                    return False
                    
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\n🛑 Interrupción por teclado detectada")
            return False
        except Exception as e:
            print(f"❌ Error monitoreando servidor: {e}")
            return False
            
        return True
    
    def cleanup_port(self):
        """Limpiar el puerto antes de reiniciar"""
        try:
            # Buscar y terminar procesos en el puerto
            result = subprocess.run(
                ['lsof', '-ti', f':{PORT}'],
                capture_output=True,
                text=True
            )
            
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    if pid:
                        print(f"🧹 Terminando proceso en puerto {PORT}: PID {pid}")
                        subprocess.run(['kill', '-9', pid], capture_output=True)
                        
                time.sleep(1)  # Esperar a que se libere el puerto
                
        except Exception as e:
            print(f"⚠️ Error limpiando puerto: {e}")
    
    def run(self):
        """Ejecutar el servidor con reinicio automático"""
        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Verificar dependencias
        if not self.check_dependencies():
            return False
        
        print("🔄 SERVIDOR ROBUSTO CON REINICIO AUTOMÁTICO")
        print("=" * 50)
        print(f"🎯 Máximo de reinicios: {MAX_RESTARTS}")
        print(f"⏰ Delay entre reinicios: {RESTART_DELAY}s")
        print(f"🌐 URL: http://localhost:{PORT}")
        print("💡 Usa Ctrl+C para detener")
        print("-" * 50)
        
        while self.running and self.restart_count < MAX_RESTARTS:
            # Limpiar puerto antes de iniciar
            if self.restart_count > 0:
                print(f"🔄 Reintento #{self.restart_count}")
                self.cleanup_port()
                time.sleep(RESTART_DELAY)
            
            # Iniciar servidor
            if not self.start_server():
                self.restart_count += 1
                continue
            
            # Monitorear servidor
            server_running = self.monitor_server()
            
            if not server_running and self.running:
                self.restart_count += 1
                print(f"🔄 Reiniciando servidor... ({self.restart_count}/{MAX_RESTARTS})")
            else:
                break
        
        if self.restart_count >= MAX_RESTARTS:
            print(f"❌ Máximo de reinicios ({MAX_RESTARTS}) alcanzado. Deteniendo.")
            return False
        
        return True

if __name__ == "__main__":
    print("🚀 INICIANDO SERVIDOR ROBUSTO...")
    server = RobustServer()
    success = server.run()
    
    if not success:
        print("❌ El servidor no pudo ejecutarse correctamente")
        sys.exit(1)
    else:
        print("✅ Servidor cerrado exitosamente")
