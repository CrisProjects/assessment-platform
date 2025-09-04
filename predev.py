#!/usr/bin/env python3
"""
Script predev: Mata procesos en puerto 5002 antes de iniciar el servidor
"""
import os
import subprocess
import sys
import platform

def kill_port_processes(port=5002):
    """Mata todos los procesos que usan el puerto especificado"""
    system = platform.system().lower()
    
    print(f"🔍 Buscando procesos en puerto {port}...")
    
    try:
        if system in ['darwin', 'linux']:  # macOS/Linux
            # Buscar procesos
            result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                  capture_output=True, text=True)
            
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                print(f"🎯 Encontrados {len(pids)} procesos en puerto {port}")
                
                # Matar procesos
                for pid in pids:
                    if pid:
                        print(f"💀 Matando proceso PID: {pid}")
                        subprocess.run(['kill', '-9', pid], capture_output=True)
                
                print(f"✅ Puerto {port} liberado")
            else:
                print(f"✅ Puerto {port} ya está libre")
                
        elif system == 'windows':  # Windows
            # Buscar procesos
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            pids_to_kill = []
            for line in lines:
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        if pid not in pids_to_kill:
                            pids_to_kill.append(pid)
            
            if pids_to_kill:
                print(f"🎯 Encontrados {len(pids_to_kill)} procesos en puerto {port}")
                for pid in pids_to_kill:
                    print(f"💀 Matando proceso PID: {pid}")
                    subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True)
                print(f"✅ Puerto {port} liberado")
            else:
                print(f"✅ Puerto {port} ya está libre")
                
    except FileNotFoundError as e:
        print(f"❌ Error: Comando no encontrado - {e}")
        return False
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        return False
    
    return True

def check_port_status(port=5002):
    """Verifica qué procesos están usando el puerto"""
    system = platform.system().lower()
    
    print(f"\n📊 Estado del puerto {port}:")
    
    try:
        if system in ['darwin', 'linux']:  # macOS/Linux
            result = subprocess.run(['lsof', '-i', f':{port}'], 
                                  capture_output=True, text=True)
            if result.stdout.strip():
                print(result.stdout)
            else:
                print(f"🟢 Puerto {port} libre")
                
        elif system == 'windows':  # Windows
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            found = False
            for line in lines:
                if f':{port}' in line:
                    print(line.strip())
                    found = True
            
            if not found:
                print(f"🟢 Puerto {port} libre")
                
    except Exception as e:
        print(f"❌ Error verificando puerto: {e}")

if __name__ == '__main__':
    port = 5002
    
    # Verificar argumentos
    if len(sys.argv) > 1:
        if sys.argv[1] == '--check':
            check_port_status(port)
            sys.exit(0)
        elif sys.argv[1] == '--help':
            print("Uso:")
            print("  python predev.py         - Mata procesos en puerto 5002")
            print("  python predev.py --check - Verifica estado del puerto")
            print("  python predev.py --help  - Muestra esta ayuda")
            sys.exit(0)
    
    # Matar procesos y verificar
    if kill_port_processes(port):
        check_port_status(port)
        print(f"\n🚀 Puerto {port} listo para usar")
    else:
        print(f"\n❌ Error liberando puerto {port}")
        sys.exit(1)
