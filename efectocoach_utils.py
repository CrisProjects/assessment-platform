#!/usr/bin/env python3
"""
Utilidades para el módulo EfectoCoach
Módulo demo sin guardar datos en base de datos
"""
from flask import request
import logging

logger = logging.getLogger(__name__)

def es_modo_demo(request_obj=None):
    """
    Determina si la solicitud está en modo demo.
    
    Args:
        request_obj: Objeto request de Flask (opcional, usa el global si no se pasa)
    
    Returns:
        bool: True si está en modo demo, False en caso contrario
    """
    if request_obj is None:
        request_obj = request
    
    # Verificar si la ruta contiene 'efectocoach'
    if request_obj and hasattr(request_obj, 'path'):
        if '/efectocoach' in request_obj.path or '/api/efectocoach' in request_obj.path:
            logger.info("🎯 MODO DEMO: Detectado por ruta /efectocoach")
            return True
    
    # Verificar parámetro de query
    if request_obj and hasattr(request_obj, 'args'):
        if request_obj.args.get('demo') == 'true' or request_obj.args.get('mode') == 'demo':
            logger.info("🎯 MODO DEMO: Detectado por parámetro de query")
            return True
    
    # Verificar header personalizado
    if request_obj and hasattr(request_obj, 'headers'):
        if request_obj.headers.get('X-Demo-Mode') == 'true':
            logger.info("🎯 MODO DEMO: Detectado por header X-Demo-Mode")
            return True
    
    return False


def calcular_puntaje_demo(responses):
    """
    Calcula el puntaje en memoria sin guardar nada en BD.
    Usa escala Likert de 3 puntos (1-3) como la evaluación original.
    
    Args:
        responses: Dict con las respuestas {question_id: value}
        
    Returns:
        tuple: (score, result_text, dimensional_scores)
    """
    try:
        # Convertir responses a formato de diccionario si viene como lista
        if isinstance(responses, list):
            responses_dict = {}
            for resp in responses:
                if isinstance(resp, dict):
                    q_id = resp.get('question_id') or resp.get('id')
                    value = resp.get('value') or resp.get('selected_option', 1)
                    if q_id:
                        responses_dict[str(q_id)] = int(value)
            responses = responses_dict
        
        # Obtener preguntas para mapping de dimensiones
        preguntas = obtener_preguntas_demo()
        
        # Mapear question_id a dimensión (las 7 dimensiones de la evaluación original)
        question_to_dimension = {
            1: 'Delegación',
            2: 'Estructura organizacional',
            3: 'Gestión del tiempo del dueño',
            4: 'Finanzas',
            5: 'Crecimiento estratégico',
            6: 'Bienestar personal',
            7: 'Visión a futuro'
        }
        
        # Calcular puntajes por dimensión
        dimensional_scores = {}
        dimension_counts = {}
        
        for q_id_str, value in responses.items():
            q_id = int(q_id_str)
            dimension = question_to_dimension.get(q_id)
            
            if dimension:
                # Mantener escala 1-3 (sin convertir a porcentaje)
                score_value = int(value)  # Mantener el valor 1, 2 o 3
                
                if dimension not in dimensional_scores:
                    dimensional_scores[dimension] = 0
                    dimension_counts[dimension] = 0
                
                dimensional_scores[dimension] += score_value
                dimension_counts[dimension] += 1
        
        # Promediar por dimensión
        for dimension in dimensional_scores:
            if dimension_counts[dimension] > 0:
                dimensional_scores[dimension] = round(
                    dimensional_scores[dimension] / dimension_counts[dimension], 2
                )
        
        # Calcular puntaje general (promedio de todas las dimensiones)
        if dimensional_scores:
            overall_score = sum(dimensional_scores.values()) / len(dimensional_scores)
        else:
            overall_score = 0
        
        # Generar texto de resultado
        result_text = generar_texto_resultado_demo(overall_score, dimensional_scores)
        
        logger.info(f"✅ DEMO: Puntaje calculado: {overall_score:.2f}")
        return round(overall_score, 2), result_text, dimensional_scores
        
    except Exception as e:
        logger.error(f"❌ DEMO: Error calculando puntaje: {e}")
        return 0, "Error calculando resultados", {}


def generar_texto_resultado_demo(score, dimensional_scores):
    """
    Genera el texto de resultado para modo demo.
    
    Args:
        score: Puntaje general en escala 1-3
        dimensional_scores: Dict con puntajes por dimensión (escala 1-3)
        
    Returns:
        str: Texto descriptivo del resultado
    """
    # Clasificar nivel de preparación basado en escala 1-3
    if score >= 2.5:
        nivel = "Excelente"
        descripcion = "Estás muy bien preparado para crecer en 2026. Tienes una mentalidad sólida y las herramientas necesarias para enfrentar nuevos desafíos."
    elif score >= 2.0:
        nivel = "Bueno"
        descripcion = "Tienes una buena base para crecer en 2026. Hay áreas específicas donde puedes mejorar para maximizar tu potencial."
    elif score >= 1.5:
        nivel = "En Desarrollo"
        descripcion = "Estás en camino hacia tu preparación para 2026. Te beneficiarías de trabajar en varias áreas clave de desarrollo personal y profesional."
    else:
        nivel = "Inicial"
        descripcion = "Hay mucho espacio para crecer. Este es un excelente momento para comenzar a desarrollar las habilidades y mentalidad necesarias para el futuro."
    
    # Retornar solo la descripción simple (sin formato Markdown ni detalles adicionales)
    return descripcion


def obtener_preguntas_demo():
    """
    Retorna las preguntas EXACTAS de la evaluación "Preparación para crecer 2026" 
    de forma hardcoded para modo demo (sin acceso a BD).
    
    Esta evaluación usa escala Likert de 3 puntos (1-3) con opciones específicas por dimensión.
    
    Returns:
        list: Lista de diccionarios con las 7 preguntas originales
    """
    preguntas = [
        # Delegación
        {
            'id': 1,
            'text': '¿Qué tanto depende tu negocio de ti para funcionar día a día?',
            'dimension': 'Delegación',
            'order': 1
        },
        # Estructura organizacional
        {
            'id': 2,
            'text': '¿Tu empresa tiene roles y procesos definidos?',
            'dimension': 'Estructura organizacional',
            'order': 2
        },
        # Gestión del tiempo del dueño
        {
            'id': 3,
            'text': '¿Cuántas horas al día dedicas a la operación?',
            'dimension': 'Gestión del tiempo del dueño',
            'order': 3
        },
        # Finanzas
        {
            'id': 4,
            'text': '¿Qué tan confiable y actualizada es tu información financiera?',
            'dimension': 'Finanzas',
            'order': 4
        },
        # Crecimiento estratégico
        {
            'id': 5,
            'text': '¿Cómo te sientes respecto al crecimiento en 2026?',
            'dimension': 'Crecimiento estratégico',
            'order': 5
        },
        # Bienestar personal
        {
            'id': 6,
            'text': '¿Cómo te sientes en tu rol actual?',
            'dimension': 'Bienestar personal',
            'order': 6
        },
        # Visión a futuro
        {
            'id': 7,
            'text': 'Si sigues igual un año más, ¿cómo te sentirías?',
            'dimension': 'Visión a futuro',
            'order': 7
        }
    ]
    
    logger.info(f"✅ DEMO: {len(preguntas)} preguntas cargadas desde memoria")
    return preguntas
