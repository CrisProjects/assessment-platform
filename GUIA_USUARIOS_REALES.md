# 🎯 GUÍA PARA PROBAR EL DASHBOARD DEL COACH - CASOS REALES

## 👥 USUARIOS CREADOS (Caso de empresa real)

### 🏢 **CONTEXTO**: 
Empresa de consultoría con un coach ejecutivo supervisando a 3 profesionales

---

### 👨‍💼 **COACH EJECUTIVO**
- **Usuario**: `carlos.martinez`
- **Password**: `coach2024`
- **Nombre**: Carlos Martínez (Coach Ejecutivo)
- **Dashboard**: Se redirige a `/coach-dashboard`

### 👩‍💼 **COACHEES ASIGNADOS**

#### 1. **Gerente de Ventas**
- **Usuario**: `ana.garcia`
- **Password**: `ana123`
- **Nombre**: Ana García
- **Perfil**: Gerente de Ventas con 5 años de experiencia

#### 2. **Coordinador de Proyectos**
- **Usuario**: `luis.rodriguez`
- **Password**: `luis123`
- **Nombre**: Luis Rodríguez
- **Perfil**: Coordinador de Proyectos en área de TI

#### 3. **Analista de Marketing**
- **Usuario**: `maria.lopez`
- **Password**: `maria123`
- **Nombre**: María López
- **Perfil**: Analista de Marketing Digital

---

## 🎮 **PROCESO PARA GENERAR DATOS EN EL DASHBOARD**

### **PASO 1: Completar Evaluaciones como Coachees**

1. **Ir a**: https://assessment-platform-1nuo.onrender.com/login

2. **Hacer login con cada coachee** (uno por uno):
   
   **Como Ana García:**
   - Usuario: `ana.garcia`
   - Password: `ana123`
   - Completar evaluación de asertividad (responder las 40 preguntas)
   - Simular perfil: Gerente assertiva con buenas habilidades de comunicación
   
   **Como Luis Rodríguez:**
   - Usuario: `luis.rodriguez`
   - Password: `luis123`
   - Completar evaluación de asertividad
   - Simular perfil: Coordinador más introvertido, necesita mejorar asertividad
   
   **Como María López:**
   - Usuario: `maria.lopez`
   - Password: `maria123`
   - Completar evaluación de asertividad
   - Simular perfil: Analista con tendencia agresiva en situaciones de estrés

### **PASO 2: Revisar Dashboard como Coach**

1. **Hacer login como coach**:
   - Usuario: `carlos.martinez`
   - Password: `coach2024`

2. **Explorar el dashboard**:
   - Ver estadísticas generales (3 coachees, N evaluaciones)
   - Revisar distribución de niveles de asertividad
   - Ver progreso individual de cada coachee
   - Analizar tendencias y patrones

---

## 📊 **QUÉ VERÁS EN EL DASHBOARD**

### **Estadísticas Principales:**
- **3 Coachees** asignados
- **N Evaluaciones** completadas
- **Puntuación promedio** del equipo
- **Actividad reciente** del mes

### **Visualizaciones:**
- **Gráfico circular**: Distribución de niveles (Poco/Moderado/Asertivo/Muy Asertivo)
- **Tarjetas de coachees**: Información individual con última evaluación
- **Progreso detallado**: Historial completo por persona

### **Funcionalidades:**
- **Ver detalles**: Click en cada coachee para ver progreso completo
- **Monitoreo**: Seguimiento de evolución en el tiempo
- **Análisis**: Identificar patrones y áreas de mejora

---

## 🎯 **ESCENARIOS DE PRUEBA SUGERIDOS**

### **Escenario 1: Primera Evaluación**
- Cada coachee completa su primera evaluación
- El coach ve el estado inicial del equipo

### **Escenario 2: Evaluaciones de Seguimiento**
- Después de unas semanas, repetir evaluaciones
- Ver progreso y cambios en el dashboard

### **Escenario 3: Análisis Comparativo**
- Comparar resultados entre coachees
- Identificar quién necesita más apoyo

---

## 🔧 **TROUBLESHOOTING**

### **Si el dashboard aparece vacío:**
- Verificar que los coachees hayan completado evaluaciones
- Asegurarse de estar logueado como `carlos.martinez`
- Refrescar la página

### **Si no aparecen los coachees:**
- Verificar que estén asignados al coach correcto
- Confirmar roles en `/api/debug-users`

---

## 🌐 **URL DE ACCESO**
**https://assessment-platform-1nuo.onrender.com/login**

---

## 📝 **RESUMEN DE CREDENCIALES**

| Rol | Usuario | Password | Propósito |
|-----|---------|----------|-----------|
| Coach | `carlos.martinez` | `coach2024` | Monitorear dashboard |
| Coachee | `ana.garcia` | `ana123` | Completar evaluaciones |
| Coachee | `luis.rodriguez` | `luis123` | Completar evaluaciones |
| Coachee | `maria.lopez` | `maria123` | Completar evaluaciones |
| Admin | `admin` | `admin123` | Administrar sistema |

---

**¡Ahora puedes probar el sistema como en un caso real de coaching empresarial!** 🚀

**NOTA**: Una vez que completes las evaluaciones con los coachees, el dashboard del coach se poblará automáticamente con datos reales y podrás ver todas las funcionalidades en acción.
