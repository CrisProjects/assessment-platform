"""
Funciones auxiliares para análisis de evaluaciones de asertividad para coaches
"""

def calculate_dimensional_scores_from_responses(responses):
    """Calcular puntuaciones dimensionales a partir de las respuestas almacenadas"""
    # Mapeo de preguntas a dimensiones
    question_to_dimension = {
        1: 'comunicacion',      # Pregunta 1
        2: 'opiniones',         # Pregunta 2  
        3: 'derechos',          # Pregunta 3
        4: 'comunicacion',      # Pregunta 4
        5: 'derechos',          # Pregunta 5
        6: 'derechos',          # Pregunta 6
        7: 'conflictos',        # Pregunta 7
        8: 'conflictos',        # Pregunta 8
        9: 'autoconfianza',     # Pregunta 9
        10: 'autoconfianza'     # Pregunta 10
    }
    
    dimension_scores = {
        'comunicacion': [],
        'derechos': [],
        'opiniones': [],
        'conflictos': [],
        'autoconfianza': []
    }
    
    # Agrupar respuestas por dimensión
    for response in responses:
        dimension = question_to_dimension.get(response.question_id)
        if dimension and response.selected_option:
            # Convertir respuesta a puntuación (escala Likert 1-5)
            points = response.selected_option  # 1=Totalmente en desacuerdo, 5=Totalmente de acuerdo
            dimension_scores[dimension].append(points)
    
    # Calcular promedios y convertir a escala 0-100
    final_scores = {}
    for dimension, scores in dimension_scores.items():
        if scores:
            avg_score = sum(scores) / len(scores)
            final_scores[dimension] = round((avg_score / 5) * 100, 1)
        else:
            # Si no hay preguntas para esta dimensión, usar promedio general
            all_scores = [score for scores_list in dimension_scores.values() for score in scores_list if scores_list]
            if all_scores:
                general_avg = sum(all_scores) / len(all_scores)
                final_scores[dimension] = round((general_avg / 5) * 100, 1)
            else:
                final_scores[dimension] = 50.0  # Valor neutral por defecto
    
    return final_scores

def get_assessment_strengths(dimensional_scores):
    """Identificar fortalezas basadas en las puntuaciones dimensionales"""
    strengths = []
    
    for dimension, score in dimensional_scores.items():
        if score >= 70:
            dimension_names = {
                'comunicacion': 'Comunicación Asertiva',
                'derechos': 'Defensa de Derechos',
                'opiniones': 'Expresión de Opiniones',
                'conflictos': 'Manejo de Conflictos',
                'autoconfianza': 'Autoconfianza'
            }
            strengths.append({
                'dimension': dimension_names.get(dimension, dimension),
                'score': score,
                'description': get_strength_description(dimension, score)
            })
    
    return strengths

def get_assessment_improvements(dimensional_scores):
    """Identificar áreas de mejora basadas en las puntuaciones dimensionales"""
    improvements = []
    
    for dimension, score in dimensional_scores.items():
        if score < 60:
            dimension_names = {
                'comunicacion': 'Comunicación Asertiva',
                'derechos': 'Defensa de Derechos',
                'opiniones': 'Expresión de Opiniones',
                'conflictos': 'Manejo de Conflictos',
                'autoconfianza': 'Autoconfianza'
            }
            improvements.append({
                'dimension': dimension_names.get(dimension, dimension),
                'score': score,
                'description': get_improvement_description(dimension, score)
            })
    
    return improvements

def get_strength_description(dimension, score):
    """Obtener descripción de fortaleza por dimensión"""
    descriptions = {
        'comunicacion': f'Excelente habilidad para comunicarse de manera clara y directa (Puntuación: {score}%). Mantiene un estilo comunicativo equilibrado.',
        'derechos': f'Muy buena capacidad para defender sus derechos de manera apropiada (Puntuación: {score}%). Establece límites saludables.',
        'opiniones': f'Gran facilidad para expresar opiniones personales de forma respetuosa (Puntuación: {score}%). No teme diferir de otros.',
        'conflictos': f'Excelente manejo de situaciones conflictivas (Puntuación: {score}%). Aborda los problemas de manera constructiva.',
        'autoconfianza': f'Alta confianza en sus propias habilidades y decisiones (Puntuación: {score}%). Mantiene una autoimagen positiva.'
    }
    return descriptions.get(dimension, f'Fortaleza en {dimension} (Puntuación: {score}%)')

def get_improvement_description(dimension, score):
    """Obtener descripción de área de mejora por dimensión"""
    descriptions = {
        'comunicacion': f'Oportunidad de mejorar la comunicación directa y clara (Puntuación: {score}%). Considerar practicar expresión de necesidades.',
        'derechos': f'Área de desarrollo en la defensa de derechos personales (Puntuación: {score}%). Importante trabajar en establecer límites.',
        'opiniones': f'Espacio para crecer en la expresión de opiniones personales (Puntuación: {score}%). Practicar compartir puntos de vista únicos.',
        'conflictos': f'Oportunidad de mejorar el manejo de conflictos (Puntuación: {score}%). Desarrollar estrategias de resolución constructiva.',
        'autoconfianza': f'Área de desarrollo en confianza personal (Puntuación: {score}%). Trabajar en reconocimiento de fortalezas propias.'
    }
    return descriptions.get(dimension, f'Área de mejora en {dimension} (Puntuación: {score}%)')

def get_coach_recommendations(dimensional_scores, overall_score):
    """Generar recomendaciones específicas para el coach"""
    recommendations = []
    
    # Recomendaciones basadas en puntuación general
    if overall_score < 50:
        recommendations.append("Considerar un enfoque de desarrollo integral de habilidades asertivas")
        recommendations.append("Establecer metas pequeñas y alcanzables para construir confianza")
    elif overall_score < 70:
        recommendations.append("Enfocarse en las dimensiones con menor puntuación para un desarrollo equilibrado")
        recommendations.append("Practicar situaciones específicas relacionadas con las áreas de mejora")
    else:
        recommendations.append("Mantener y refinar las fortalezas identificadas")
        recommendations.append("Considerar rol de mentor para otros en desarrollo de asertividad")
    
    # Recomendaciones específicas por dimensión
    lowest_dimension = min(dimensional_scores.items(), key=lambda x: x[1])
    highest_dimension = max(dimensional_scores.items(), key=lambda x: x[1])
    
    dimension_recommendations = {
        'comunicacion': "Ejercicios de comunicación clara y directa",
        'derechos': "Práctica en establecimiento de límites personales",
        'opiniones': "Desarrollo de confianza para expresar puntos de vista únicos",
        'conflictos': "Entrenamiento en técnicas de resolución de conflictos",
        'autoconfianza': "Trabajo en reconocimiento y valoración de logros personales"
    }
    
    if lowest_dimension[1] < 60:
        recommendations.append(f"Priorizar trabajo en: {dimension_recommendations.get(lowest_dimension[0], lowest_dimension[0])}")
    
    if highest_dimension[1] > 80:
        recommendations.append(f"Aprovechar fortaleza en {highest_dimension[0]} como base para otras áreas")
    
    return recommendations

def calculate_progress_trend(scores):
    """Calcular tendencia de progreso basada en las puntuaciones"""
    if len(scores) < 2:
        return 'insufficient_data'
    
    # Ordenar scores cronológicamente (más recientes primero, así que revertir)
    scores = list(reversed(scores))
    
    recent_scores = scores[-3:] if len(scores) >= 3 else scores
    early_scores = scores[:3] if len(scores) >= 3 else scores[:-1] if len(scores) > 1 else [scores[0]]
    
    recent_avg = sum(recent_scores) / len(recent_scores)
    early_avg = sum(early_scores) / len(early_scores)
    
    difference = recent_avg - early_avg
    
    if difference > 5:
        return 'improving'
    elif difference < -5:
        return 'declining'
    else:
        return 'stable'
