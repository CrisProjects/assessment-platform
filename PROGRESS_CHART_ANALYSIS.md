# 📊 DOCUMENTACIÓN: GRÁFICO DE TENDENCIA DE PROGRESO

## 🎯 **Cómo Funciona el Gráfico de Tendencia de Progreso**

### **1. FUENTE DE DATOS (Backend)**

#### **API Endpoint:** `/api/coach/dashboard-stats`
- **Archivo:** `app_complete.py` líneas 1037-1150
- **Función:** `api_coach_dashboard_stats()`

#### **Consulta de Datos:**
```python
# Obtener todos los coachees del coach actual
coachees = User.query.filter_by(coach_id=current_user.id, role='coachee').all()

# Para cada coachee, obtener evaluaciones de los últimos 6 meses
six_months_ago = datetime.utcnow() - timedelta(days=180)
coachee_assessments = AssessmentResult.query.filter(
    AssessmentResult.user_id == coachee.id,
    AssessmentResult.completed_at >= six_months_ago
).order_by(AssessmentResult.completed_at).all()
```

#### **Estructura de Datos Enviada:**
```json
{
  "progress_data": [
    {
      "coachee_name": "Ana García",
      "coachee_id": 123,
      "assessments": [
        {"date": "2025-03-21T18:04:16.690819", "score": 30.0},
        {"date": "2025-04-18T18:04:16.690816", "score": 48.5},
        {"date": "2025-05-27T18:04:16.690808", "score": 69.8},
        {"date": "2025-06-08T18:04:16.690803", "score": 78.0}
      ]
    }
  ]
}
```

### **2. PROCESAMIENTO (Frontend)**

#### **Archivo:** `templates/coach_dashboard.html` líneas 1605-1720
#### **Función:** `updateProgressChart(progressData)`

#### **Transformación de Datos:**
```javascript
// Crear datasets para Chart.js
const datasets = progressData.map((coachee, index) => {
    return {
        label: coachee.coachee_name,
        data: coachee.assessments.map(assessment => ({
            x: new Date(assessment.date),  // Convertir fecha a objeto Date
            y: assessment.score            // Puntuación como número
        })),
        borderColor: colors[index % colors.length],
        // ... configuración visual
    };
});
```

### **3. VISUALIZACIÓN (Chart.js)**

#### **Tipo de Gráfico:** Line Chart con escala temporal
#### **Configuración:**
- **Eje X:** Tiempo (fechas de evaluaciones)
- **Eje Y:** Puntuación (0-100%)
- **Líneas:** Una por cada coachee
- **Puntos:** Cada evaluación individual

#### **Características:**
- ✅ **Múltiples coachees** - Cada uno con su propia línea y color
- ✅ **Escala temporal** - Eje X muestra fechas reales
- ✅ **Tendencia visual** - Líneas con tensión para suavizar curvas
- ✅ **Tooltips informativos** - Muestran coachee + puntuación + fecha
- ✅ **Leyenda** - Identifica cada coachee por color

### **4. DATOS REALES DISPONIBLES**

#### **Coach Principal (ID: 2) - 28 evaluaciones:**

**Ana García:** 5 evaluaciones (Tendencia ↗️ ASCENDENTE)
- 2025-03-21: 30.0% → 2025-06-08: 78.0% (+48% mejora)

**Carlos Ruiz:** 6 evaluaciones (Tendencia ↕️ VARIABLE)
- 2025-02-20: 37.2% → 2025-06-16: 60.0% (+23% mejora)

**David Chen:** 6 evaluaciones (Tendencia ↗️ ASCENDENTE)
- 2025-02-09: 42.0% → 2025-06-20: 81.0% (+39% mejora)

**Elena Rodríguez:** 4 evaluaciones (Tendencia ↗️ FUERTE ASCENDENTE)
- 2025-03-27: 22.0% → 2025-06-20: 83.0% (+61% mejora notable)

**María López:** 7 evaluaciones (Tendencia ↗️ GRADUAL)
- 2025-01-19: 25.0% → 2025-06-16: 59.0% (+34% mejora)

### **5. LÓGICA DE ACTUALIZACIÓN**

#### **Frecuencia:** Cada 30 segundos (auto-refresh)
```javascript
setInterval(() => {
    loadDashboardStats();  // Actualiza gráfico automáticamente
}, 30000);
```

#### **Flujo Completo:**
1. **Frontend** llama a `/api/coach/dashboard-stats`
2. **Backend** consulta `AssessmentResult` + `User` tables
3. **Datos** se agrupan por coachee con timestamps
4. **JavaScript** transforma datos para Chart.js
5. **Gráfico** se renderiza/actualiza automáticamente

### **6. VENTAJAS DEL DISEÑO ACTUAL**

- ✅ **Datos reales** - Toma directamente de la tabla `assessment_result`
- ✅ **Filtrado temporal** - Solo últimos 6 meses (relevante)
- ✅ **Multi-coachee** - Compara progreso de todos los coachees
- ✅ **Visualización clara** - Tendencias fáciles de identificar
- ✅ **Actualización automática** - Datos siempre actualizados
- ✅ **Escalable** - Funciona con cualquier número de coachees/evaluaciones

### **7. EJEMPLO DE TENDENCIA REAL**

**Elena Rodríguez** muestra la mejor tendencia de progreso:
```
22% (Mar) → 54.7% (Abr) → 56.7% (May) → 83% (Jun)
📈 Crecimiento constante y significativo (+61% total)
```

## ✅ **CONCLUSIÓN**

El gráfico de tendencia de progreso **SÍ está tomando los resultados reales de las evaluaciones** y mostrando correctamente las tendencias de cada coachee a lo largo del tiempo. Los datos provienen directamente de la tabla `assessment_result` y se actualizan automáticamente.
