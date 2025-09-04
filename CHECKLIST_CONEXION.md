# 📋 CHECKLIST: Arrancar Assessment Platform sin perder conexión

## ✅ Pre-requisitos
- [ ] Python 3.7+ instalado
- [ ] Dependencias instaladas (`pip install -r requirements.txt`)
- [ ] VS Code configurado con settings.json recomendado
- [ ] Scripts ejecutables (`chmod +x *.sh`)

## 🚀 Método 1: Script automático (RECOMENDADO)
```bash
./start_local.sh
```

## 🔧 Método 2: Paso a paso manual
1. [ ] **Limpiar puerto**: `python3 predev.py`
2. [ ] **Verificar limpieza**: `python3 predev.py --check`
3. [ ] **Iniciar servidor**: `python3 start_server_stable.py`
4. [ ] **Verificar en navegador**: http://localhost:5002

## 🎯 Método 3: Desde VS Code (Tareas)
1. [ ] `Ctrl+Shift+P` → "Tasks: Run Task"
2. [ ] Seleccionar "🔄 Reiniciar Servidor"
3. [ ] El puerto se limpia y el servidor inicia automáticamente

## 🔍 Comandos de diagnóstico

### macOS/Linux:
```bash
# Ver procesos en puerto 5002
lsof -i :5002

# Matar procesos en puerto 5002
lsof -ti:5002 | xargs kill -9

# Ver todos los procesos Python
ps aux | grep python

# Matar todos los procesos Python
pkill -f python
```

### Windows:
```cmd
# Ver procesos en puerto 5002
netstat -ano | findstr :5002

# Matar proceso por PID
taskkill /F /PID <PID>

# Ver procesos Python
tasklist | findstr python

# Matar procesos Python
taskkill /F /IM python.exe
```

## 🛠️ Solución de problemas

### ❌ Puerto ocupado
```bash
python3 predev.py
# o manualmente:
lsof -ti:5002 | xargs kill -9
```

### ❌ Servidor no inicia
1. [ ] Verificar dependencias: `pip install -r requirements.txt`
2. [ ] Verificar Python: `python3 --version`
3. [ ] Verificar app.py existe
4. [ ] Ver logs de error en terminal

### ❌ Conexión se pierde
1. [ ] **NO usar debug=True** (ya configurado)
2. [ ] **NO usar auto-reload** (ya configurado)  
3. [ ] Reiniciar: `python3 predev.py && python3 start_server_stable.py`

### ❌ VS Code no detecta servidor
1. [ ] Verificar settings.json aplicado
2. [ ] Reiniciar VS Code
3. [ ] Verificar puerto en navegador: http://localhost:5002

## 🔒 Configuración estable aplicada

### ✅ Puerto fijo: 5002
- No cambia automáticamente si está ocupado
- Se limpia antes de cada inicio
- Error claro si no se puede usar

### ✅ Sin auto-reload
- `debug=False` 
- `use_reloader=False`
- No se reinicia con cambios de código

### ✅ Conexiones estables
- `threaded=True` para mejor concurrencia
- Manejo de errores robusto
- Limpieza automática de puerto

## 🎯 URLs importantes
- **Principal**: http://localhost:5002
- **Dashboard Coachee**: http://localhost:5002/coachee-dashboard
- **Admin Dashboard**: http://localhost:5002/admin
- **API Status**: http://localhost:5002/api/status

## 🆘 Comandos de emergencia

### Reinicio completo:
```bash
# Matar todo Python
pkill -f python
# Limpiar puerto
python3 predev.py
# Iniciar limpio
python3 start_server_stable.py
```

### Reset VS Code:
1. `Ctrl+Shift+P` → "Developer: Reload Window"
2. Cerrar todas las terminales
3. Ejecutar tarea "🔄 Reiniciar Servidor"

## 📝 Notas importantes
- ⚠️ **NO uses `python app.py` directamente** (usa start_server_stable.py)
- ⚠️ **NO habilites debug** en producción local (ya configurado)
- ⚠️ **NO uses Live Server** si tienes servidor Flask corriendo
- ✅ **SÍ usa** las tareas de VS Code para mejor gestión
- ✅ **SÍ limpia** el puerto antes de cada inicio
