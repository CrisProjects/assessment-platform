// Simulación del comportamiento del frontend
// Simula las preguntas de DISC que llegan de la API

const questions = [
    { id: 21, order: 1, text: "Me gusta tomar decisiones rápidas y asumir riesgos" },
    { id: 22, order: 2, text: "Prefiero trabajar en equipo y motivar a otros" },
    { id: 23, order: 3, text: "Valoro la estabilidad y la armonía en el trabajo" },
    { id: 24, order: 4, text: "Me enfoco en los detalles y la precisión" },
    { id: 25, order: 5, text: "Soy directo al comunicar mis ideas" },
    { id: 26, order: 6, text: "Disfruto conocer gente nueva y socializar" },
    { id: 27, order: 7, text: "Prefiero rutinas establecidas y predecibles" },
    { id: 28, order: 8, text: "Analizo cuidadosamente antes de tomar decisiones" },
    { id: 29, order: 9, text: "Me siento cómodo liderando proyectos desafiantes" },
    { id: 30, order: 10, text: "Soy optimista y entusiasta con nuevas ideas" },
    { id: 31, order: 11, text: "Evito conflictos y busco consenso" },
    { id: 32, order: 12, text: "Sigo procedimientos y normas establecidas" },
    { id: 33, order: 13, text: "Actúo con determinación para alcanzar objetivos" },
    { id: 34, order: 14, text: "Inspiro confianza y genero entusiasmo en otros" },
    { id: 35, order: 15, text: "Soy leal y comprometido con mi equipo" },
    { id: 36, order: 16, text: "Busco perfección en mi trabajo" }
];

let currentQuestionIndex = 0;

function showCurrentQuestion() {
    const question = questions[currentQuestionIndex];
    const displayNumber = currentQuestionIndex + 1;
    
    console.log(`🎯 Mostrando pregunta ${displayNumber} de ${questions.length}`);
    console.log(`   ID: ${question.id}, Order: ${question.order}`);
    console.log(`   Texto: ${question.text}`);
    console.log(`   currentQuestionIndex: ${currentQuestionIndex}`);
    console.log("");
}

// Simular la primera pregunta
console.log("🔍 SIMULACIÓN DEL FRONTEND - NUMERACIÓN DE PREGUNTAS:");
console.log("=".repeat(60));

// Mostrar las primeras 5 preguntas
for (let i = 0; i < 5 && i < questions.length; i++) {
    currentQuestionIndex = i;
    showCurrentQuestion();
}

console.log("✅ CONCLUSIÓN: El frontend debería mostrar:");
console.log("   Pregunta 1, 2, 3, 4, 5... (secuencial)");
console.log("");
console.log("❓ Si el usuario ve 1, 3, 5... el problema podría estar en:");
console.log("   1. JavaScript que modifica currentQuestionIndex");
console.log("   2. CSS que oculta preguntas pares");
console.log("   3. Filtros en el frontend");
console.log("   4. Problema de visualización del navegador");
