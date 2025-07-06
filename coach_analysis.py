#!/usr/bin/env python3
"""
Módulo de análisis avanzado para coaches
Proporciona funciones de análisis dimensional y recomendaciones personalizadas
"""

from datetime import datetime

def calculate_dimensional_scores_from_responses(responses):
    """
    Calcula puntuaciones dimensionales a partir de respuestas
    
    Args:
        responses (dict): Diccionario con las respuestas del usuario
        
    Returns:
        dict: Puntuaciones por dimensión
    """
    # Mapeo de preguntas a dimensiones
    question_to_dimension = {
        0: 'conflictos',       # Pregunta 1
        1: 'derechos',         # Pregunta 2
        2: 'opiniones',        # Pregunta 3
        3: 'derechos',         # Pregunta 4
        4: 'comunicacion',     # Pregunta 5
        5: 'comunicacion',     # Pregunta 6
        6: 'autoconfianza',    # Pregunta 7
        7: 'conflictos',       # Pregunta 8
        8: 'conflictos',       # Pregunta 9
        9: 'autoconfianza'     # Pregunta 10
    }
    
    dimension_scores = {
        'comunicacion': [],
        'derechos': [],
        'opiniones': [],
        'conflictos': [],
        'autoconfianza': []
    }
    
    # Agrupar respuestas por dimensión
    for question_index, answer in responses.items():
        try:
            idx = int(question_index)
            answer_value = int(answer)
            
            # Validar que la respuesta esté en el rango correcto (1-5)
            if not (1 <= answer_value <= 5):
                continue
                
            if idx in question_to_dimension:
                dimension = question_to_dimension[idx]
                dimension_scores[dimension].append(answer_value)
        except (ValueError, TypeError):
            continue
    
    # Calcular promedio por dimensión y convertir a porcentaje
    final_scores = {}
    for dimension, scores in dimension_scores.items():
        if scores:
            avg_score = sum(scores) / len(scores)
            # Convertir de escala 1-5 a 0-100
            percentage = ((avg_score - 1) / 4) * 100
            final_scores[dimension] = round(percentage, 1)
        else:
            final_scores[dimension] = 0
    
    return final_scores


def get_assessment_strengths(dimensional_scores):
    """
    Identifica las fortalezas principales basadas en las puntuaciones dimensionales
    
    Args:
        dimensional_scores (dict): Puntuaciones por dimensión
        
    Returns:
        list: Lista de fortalezas identificadas
    """
    strengths = []
    
    for dimension, score in dimensional_scores.items():
        if score >= 75:  # Puntuación alta
            dimension_names = {
                'comunicacion': 'Comunicación Directa',
                'derechos': 'Defensa de Derechos',
                'opiniones': 'Expresión de Opiniones',
                'conflictos': 'Manejo de Conflictos',
                'autoconfianza': 'Autoconfianza'
            }
            
            strength_descriptions = {
                'comunicacion': 'Excelente capacidad para expresar ideas de manera clara y directa',
                'derechos': 'Fuerte habilidad para defender sus derechos de manera asertiva',
                'opiniones': 'Gran facilidad para compartir puntos de vista y opiniones',
                'conflictos': 'Manejo efectivo de situaciones difíciles y conflictos',
                'autoconfianza': 'Alta confianza en sus propias capacidades y decisiones'
            }
            
            strengths.append({
                'dimension': dimension_names.get(dimension, dimension),
                'score': score,
                'description': strength_descriptions.get(dimension, f'Puntuación alta en {dimension}')
            })
    
    # Ordenar por puntuación descendente
    strengths.sort(key=lambda x: x['score'], reverse=True)
    
    return strengths


def get_assessment_improvements(dimensional_scores):
    """
    Identifica las áreas de mejora basadas en las puntuaciones dimensionales
    
    Args:
        dimensional_scores (dict): Puntuaciones por dimensión
        
    Returns:
        list: Lista de áreas de mejora identificadas
    """
    improvements = []
    
    for dimension, score in dimensional_scores.items():
        if score < 60:  # Puntuación que necesita mejora
            dimension_names = {
                'comunicacion': 'Comunicación Directa',
                'derechos': 'Defensa de Derechos',
                'opiniones': 'Expresión de Opiniones',
                'conflictos': 'Manejo de Conflictos',
                'autoconfianza': 'Autoconfianza'
            }
            
            improvement_descriptions = {
                'comunicacion': 'Desarrollar habilidades para expresar ideas de manera más clara y directa',
                'derechos': 'Fortalecer la capacidad para defender derechos propios de manera asertiva',
                'opiniones': 'Mejorar la facilidad para compartir puntos de vista en diferentes situaciones',
                'conflictos': 'Desarrollar estrategias más efectivas para manejar situaciones difíciles',
                'autoconfianza': 'Trabajar en el fortalecimiento de la confianza personal y autoestima'
            }
            
            improvement_actions = {
                'comunicacion': [
                    'Practicar técnicas de comunicación asertiva',
                    'Trabajar en la claridad del mensaje',
                    'Desarrollar habilidades de escucha activa'
                ],
                'derechos': [
                    'Aprender a establecer límites saludables',
                    'Practicar decir "no" de manera respetuosa',
                    'Desarrollar autoconocimiento de los propios derechos'
                ],
                'opiniones': [
                    'Practicar expresar opiniones en entornos seguros',
                    'Desarrollar confianza en el propio juicio',
                    'Aprender técnicas para manejar el desacuerdo'
                ],
                'conflictos': [
                    'Aprender estrategias de resolución de conflictos',
                    'Desarrollar habilidades de negociación',
                    'Practicar mantener la calma en situaciones tensas'
                ],
                'autoconfianza': [
                    'Trabajar en el autoconocimiento y autoaceptación',
                    'Desarrollar un diálogo interno positivo',
                    'Celebrar logros y aprender de los errores'
                ]
            }
            
            improvements.append({
                'dimension': dimension_names.get(dimension, dimension),
                'score': score,
                'description': improvement_descriptions.get(dimension, f'Área de mejora en {dimension}'),
                'suggested_actions': improvement_actions.get(dimension, [])
            })
    
    # Ordenar por puntuación ascendente (peores primero)
    improvements.sort(key=lambda x: x['score'])
    
    return improvements


def get_coach_recommendations(dimensional_scores, user_profile=None):
    """
    Genera recomendaciones específicas para el coach basadas en el análisis
    
    Args:
        dimensional_scores (dict): Puntuaciones por dimensión
        user_profile (dict, optional): Información adicional del usuario
        
    Returns:
        dict: Recomendaciones estructuradas para el coach
    """
    recommendations = {
        'priority_areas': [],
        'development_plan': [],
        'coaching_strategies': [],
        'follow_up_suggestions': []
    }
    
    # Calcular puntuación promedio
    avg_score = sum(dimensional_scores.values()) / len(dimensional_scores)
    
    # Identificar áreas prioritarias (puntuación más baja)
    sorted_dimensions = sorted(dimensional_scores.items(), key=lambda x: x[1])
    
    for dimension, score in sorted_dimensions[:2]:  # Top 2 áreas prioritarias
        dimension_names = {
            'comunicacion': 'Comunicación Directa',
            'derechos': 'Defensa de Derechos',
            'opiniones': 'Expresión de Opiniones',
            'conflictos': 'Manejo de Conflictos',
            'autoconfianza': 'Autoconfianza'
        }
        
        recommendations['priority_areas'].append({
            'dimension': dimension_names.get(dimension, dimension),
            'score': score,
            'priority_level': 'Alta' if score < 40 else 'Media'
        })
    
    # Plan de desarrollo basado en puntuación general
    if avg_score >= 75:
        recommendations['development_plan'] = [
            'Enfoque en refinamiento y perfeccionamiento de habilidades',
            'Desarrollo de habilidades de liderazgo y mentoría',
            'Aplicación avanzada de técnicas asertivas en contextos complejos'
        ]
    elif avg_score >= 60:
        recommendations['development_plan'] = [
            'Consolidación de habilidades básicas de asertividad',
            'Práctica en situaciones variadas y retadoras',
            'Desarrollo de confianza en contextos específicos'
        ]
    elif avg_score >= 40:
        recommendations['development_plan'] = [
            'Establecimiento de fundamentos sólidos en asertividad',
            'Práctica gradual en situaciones controladas',
            'Desarrollo de autoconciencia y autoconfianza básica'
        ]
    else:
        recommendations['development_plan'] = [
            'Inicio con conceptos básicos de asertividad',
            'Trabajo en autoestima y autoconocimiento',
            'Establecimiento de un entorno seguro para la práctica'
        ]
    
    # Estrategias de coaching específicas
    low_scores = [dim for dim, score in dimensional_scores.items() if score < 50]
    
    coaching_strategies_map = {
        'comunicacion': [
            'Role-playing para practicar comunicación directa',
            'Ejercicios de estructuración de mensajes claros',
            'Técnicas de respiración y control de ansiedad al hablar'
        ],
        'derechos': [
            'Ejercicios de identificación de derechos personales',
            'Práctica de establecimiento de límites',
            'Simulación de situaciones de negociación'
        ],
        'opiniones': [
            'Técnicas para expresar desacuerdo respetuosamente',
            'Desarrollo de argumentación constructiva',
            'Práctica en grupos pequeños para ganar confianza'
        ],
        'conflictos': [
            'Entrenamiento en técnicas de resolución de conflictos',
            'Simulación de situaciones difíciles',
            'Desarrollo de inteligencia emocional'
        ],
        'autoconfianza': [
            'Ejercicios de autoafirmación positiva',
            'Técnicas de visualización y preparación mental',
            'Celebración de pequeños logros y progreso'
        ]
    }
    
    for dimension in low_scores:
        if dimension in coaching_strategies_map:
            recommendations['coaching_strategies'].extend(coaching_strategies_map[dimension])
    
    # Sugerencias de seguimiento
    recommendations['follow_up_suggestions'] = [
        'Reevaluación en 3-6 meses para medir progreso',
        'Establecimiento de objetivos específicos y medibles',
        'Registro de situaciones de práctica y reflexiones',
        'Feedback regular sobre aplicación de técnicas aprendidas'
    ]
    
    return recommendations


def calculate_progress_trend(assessment_history):
    """
    Calcula tendencias de progreso basadas en evaluaciones históricas
    
    Args:
        assessment_history (list): Lista de evaluaciones históricas
        
    Returns:
        dict: Análisis de tendencias y progreso
    """
    if not assessment_history or len(assessment_history) < 2:
        return {
            'trend': 'insufficient_data',
            'message': 'Se requieren al menos 2 evaluaciones para calcular tendencias',
            'progress_percentage': 0,
            'dimensional_trends': {}
        }
    
    # Ordenar por fecha
    sorted_assessments = sorted(assessment_history, key=lambda x: x.get('date', ''))
    
    first_assessment = sorted_assessments[0]
    latest_assessment = sorted_assessments[-1]
    
    # Calcular progreso general
    first_score = first_assessment.get('total_score', 0)
    latest_score = latest_assessment.get('total_score', 0)
    
    progress_percentage = ((latest_score - first_score) / first_score * 100) if first_score > 0 else 0
    
    # Determinar tendencia general
    if progress_percentage > 10:
        trend = 'improving'
        trend_message = 'Tendencia positiva de mejora'
    elif progress_percentage < -10:
        trend = 'declining'
        trend_message = 'Tendencia de declive - requiere atención'
    else:
        trend = 'stable'
        trend_message = 'Progreso estable'
    
    # Analizar tendencias dimensionales
    dimensional_trends = {}
    first_dimensional = first_assessment.get('dimensional_scores', {})
    latest_dimensional = latest_assessment.get('dimensional_scores', {})
    
    for dimension in first_dimensional.keys():
        if dimension in latest_dimensional:
            first_dim_score = first_dimensional[dimension]
            latest_dim_score = latest_dimensional[dimension]
            
            if first_dim_score > 0:
                dim_progress = ((latest_dim_score - first_dim_score) / first_dim_score * 100)
                dimensional_trends[dimension] = {
                    'progress_percentage': round(dim_progress, 1),
                    'trend': 'improving' if dim_progress > 5 else 'declining' if dim_progress < -5 else 'stable'
                }
    
    return {
        'trend': trend,
        'message': trend_message,
        'progress_percentage': round(progress_percentage, 1),
        'dimensional_trends': dimensional_trends,
        'assessments_analyzed': len(sorted_assessments),
        'time_span_days': _calculate_time_span(sorted_assessments)
    }


def _calculate_time_span(assessments):
    """
    Calcula el período de tiempo entre la primera y última evaluación
    
    Args:
        assessments (list): Lista de evaluaciones ordenadas por fecha
        
    Returns:
        int: Número de días entre evaluaciones
    """
    try:
        from datetime import datetime
        
        first_date_str = assessments[0].get('date', '')
        last_date_str = assessments[-1].get('date', '')
        
        first_date = datetime.fromisoformat(first_date_str.replace('Z', '+00:00'))
        last_date = datetime.fromisoformat(last_date_str.replace('Z', '+00:00'))
        
        return (last_date - first_date).days
    except:
        return 0


def generate_detailed_report(user_id, dimensional_scores, assessment_history=None):
    """
    Genera un reporte detallado completo para el coach
    
    Args:
        user_id (int): ID del usuario evaluado
        dimensional_scores (dict): Puntuaciones dimensionales actuales
        assessment_history (list, optional): Historial de evaluaciones
        
    Returns:
        dict: Reporte completo estructurado
    """
    report = {
        'user_id': user_id,
        'assessment_date': datetime.now().isoformat(),
        'dimensional_scores': dimensional_scores,
        'overall_score': sum(dimensional_scores.values()) / len(dimensional_scores),
        'strengths': get_assessment_strengths(dimensional_scores),
        'improvements': get_assessment_improvements(dimensional_scores),
        'coach_recommendations': get_coach_recommendations(dimensional_scores),
        'progress_analysis': calculate_progress_trend(assessment_history) if assessment_history else None
    }
    
    # Determinar nivel de asertividad
    overall_score = report['overall_score']
    if overall_score >= 80:
        report['assertiveness_level'] = 'Muy Asertivo'
    elif overall_score >= 60:
        report['assertiveness_level'] = 'Asertivo'
    elif overall_score >= 40:
        report['assertiveness_level'] = 'Moderadamente Asertivo'
    else:
        report['assertiveness_level'] = 'Poco Asertivo'
    
    return report


# Función de compatibilidad para la aplicación principal
if __name__ == "__main__":
    # Ejemplo de uso
    sample_responses = {
        '0': 4,  # Pregunta 1
        '1': 3,  # Pregunta 2
        '2': 5,  # Pregunta 3
        '3': 2,  # Pregunta 4
        '4': 4,  # Pregunta 5
        '5': 3,  # Pregunta 6
        '6': 4,  # Pregunta 7
        '7': 3,  # Pregunta 8
        '8': 4,  # Pregunta 9
        '9': 5   # Pregunta 10
    }
    
    scores = calculate_dimensional_scores_from_responses(sample_responses)
    print("Puntuaciones dimensionales:", scores)
    
    strengths = get_assessment_strengths(scores)
    print("Fortalezas:", strengths)
    
    improvements = get_assessment_improvements(scores)
    print("Áreas de mejora:", improvements)
    
    recommendations = get_coach_recommendations(scores)
    print("Recomendaciones para coach:", recommendations)
