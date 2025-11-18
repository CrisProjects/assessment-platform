#!/usr/bin/env python3
"""
Utilidades para el módulo TestPersonal
Módulo demo sin guardar datos en base de datos
Evaluación de 4 áreas de vida con respuestas Sí/No
"""
from flask import request
import logging

logger = logging.getLogger(__name__)

def es_modo_demo_personal(request_obj=None):
    """
    Determina si la solicitud está en modo demo para TestPersonal.
    
    Args:
        request_obj: Objeto request de Flask (opcional, usa el global si no se pasa)
    
    Returns:
        bool: True si está en modo demo, False en caso contrario
    """
    if request_obj is None:
        request_obj = request
    
    # Verificar si la ruta contiene 'testpersonal'
    if request_obj and hasattr(request_obj, 'path'):
        if '/testpersonal' in request_obj.path or '/api/testpersonal' in request_obj.path:
            logger.info("🎯 MODO DEMO TESTPERSONAL: Detectado por ruta /testpersonal")
            return True
    
    # Verificar parámetro de query
    if request_obj and hasattr(request_obj, 'args'):
        if request_obj.args.get('demo') == 'testpersonal':
            logger.info("🎯 MODO DEMO TESTPERSONAL: Detectado por parámetro de query")
            return True
    
    return False


def obtener_preguntas_testpersonal():
    """
    Retorna las 20 afirmaciones del TestPersonal organizadas en 4 áreas.
    Respuestas binarias: Sí (1) / No (0)
    
    Returns:
        list: Lista de diccionarios con las 20 afirmaciones
    """
    preguntas = [
        # ÁREA PROFESIONAL / TRABAJO (5 preguntas)
        {
            'id': 1,
            'text': 'Siento que tengo más potencial del que estoy usando en mi trabajo.',
            'area': 'Profesional',
            'icon': '💼',
            'order': 1
        },
        {
            'id': 2,
            'text': 'Me cuesta delegar o tomar decisiones con claridad.',
            'area': 'Profesional',
            'icon': '💼',
            'order': 2
        },
        {
            'id': 3,
            'text': 'Estoy en una transición de rol o necesito re-inventarme profesionalmente.',
            'area': 'Profesional',
            'icon': '💼',
            'order': 3
        },
        {
            'id': 4,
            'text': 'Estoy liderando personas, pero no me siento preparada/o.',
            'area': 'Profesional',
            'icon': '💼',
            'order': 4
        },
        {
            'id': 5,
            'text': 'Mi trabajo me está dejando sin energía ni motivación.',
            'area': 'Profesional',
            'icon': '💼',
            'order': 5
        },
        
        # ÁREA PERSONAL / EMOCIONAL (5 preguntas)
        {
            'id': 6,
            'text': 'Me cuesta poner límites o priorizarme.',
            'area': 'Personal/Emocional',
            'icon': '💬',
            'order': 6
        },
        {
            'id': 7,
            'text': 'Dudo de mí misma/o con frecuencia, aunque sé que tengo capacidades.',
            'area': 'Personal/Emocional',
            'icon': '💬',
            'order': 7
        },
        {
            'id': 8,
            'text': 'Me comparo mucho con los demás y me frustro fácilmente.',
            'area': 'Personal/Emocional',
            'icon': '💬',
            'order': 8
        },
        {
            'id': 9,
            'text': 'Estoy buscando más claridad sobre quién soy y qué quiero.',
            'area': 'Personal/Emocional',
            'icon': '💬',
            'order': 9
        },
        {
            'id': 10,
            'text': 'Siento que me saboteo cuando estoy por lograr algo importante.',
            'area': 'Personal/Emocional',
            'icon': '💬',
            'order': 10
        },
        
        # ÁREA DE PROPÓSITO / ELECCIONES (5 preguntas)
        {
            'id': 11,
            'text': 'Me siento desconectada/o de mi propósito o motivación profunda.',
            'area': 'Propósito/Elecciones',
            'icon': '🧭',
            'order': 11
        },
        {
            'id': 12,
            'text': 'Estoy en una etapa de cambio o búsqueda personal.',
            'area': 'Propósito/Elecciones',
            'icon': '🧭',
            'order': 12
        },
        {
            'id': 13,
            'text': 'Quiero tomar una decisión importante, pero estoy bloqueada/o.',
            'area': 'Propósito/Elecciones',
            'icon': '🧭',
            'order': 13
        },
        {
            'id': 14,
            'text': 'Estoy haciendo cosas que ya no me representan.',
            'area': 'Propósito/Elecciones',
            'icon': '🧭',
            'order': 14
        },
        {
            'id': 15,
            'text': 'Necesito encontrar más sentido en lo que hago.',
            'area': 'Propósito/Elecciones',
            'icon': '🧭',
            'order': 15
        },
        
        # BIENESTAR Y ENERGÍA PERSONAL (5 preguntas)
        {
            'id': 16,
            'text': 'Me cuesta sostener hábitos que me hacen bien.',
            'area': 'Bienestar',
            'icon': '❤️',
            'order': 16
        },
        {
            'id': 17,
            'text': 'Siento que todo me exige más de lo que puedo dar.',
            'area': 'Bienestar',
            'icon': '❤️',
            'order': 17
        },
        {
            'id': 18,
            'text': 'Quiero recuperar mi foco, mi energía y mi paz mental.',
            'area': 'Bienestar',
            'icon': '❤️',
            'order': 18
        },
        {
            'id': 19,
            'text': 'Vivo en modo "responder al día" y no en modo "diseñar mi vida".',
            'area': 'Bienestar',
            'icon': '❤️',
            'order': 19
        },
        {
            'id': 20,
            'text': 'Quiero sentirme más liviana/o, ordenada/o y en coherencia conmigo misma/o.',
            'area': 'Bienestar',
            'icon': '❤️',
            'order': 20
        }
    ]
    
    logger.info(f"✅ TESTPERSONAL DEMO: {len(preguntas)} preguntas cargadas desde memoria")
    return preguntas


def calcular_puntaje_testpersonal(responses):
    """
    Calcula el puntaje por área sin guardar nada en BD.
    Respuestas: Sí = 1, No = 0
    Escala por área: 0-5 (suma de las 5 respuestas)
    Escala general: 0-20 (suma de todas las respuestas)
    
    INTERPRETACIÓN:
    - Mayor puntaje = Mayor necesidad de coaching en esa área
    - 0-1: Verde (área fuerte)
    - 2: Amarillo (área de atención)
    - 3-5: Rojo (área prioritaria para coaching)
    
    Args:
        responses: Dict con las respuestas {question_id: value}
        
    Returns:
        tuple: (overall_score, overall_percentage, result_text, area_scores)
    """
    try:
        # Convertir responses a formato de diccionario si viene como lista
        if isinstance(responses, list):
            responses_dict = {}
            for resp in responses:
                if isinstance(resp, dict):
                    q_id = resp.get('question_id') or resp.get('id')
                    value = resp.get('value') or resp.get('selected_option', 0)
                    if q_id:
                        responses_dict[str(q_id)] = int(value)
            responses = responses_dict
        
        # Obtener preguntas para mapping de áreas
        preguntas = obtener_preguntas_testpersonal()
        
        # Mapear question_id a área
        question_to_area = {}
        for pregunta in preguntas:
            question_to_area[pregunta['id']] = pregunta['area']
        
        # Calcular puntajes por área (suma simple de respuestas Sí)
        area_scores = {
            'Profesional': 0,
            'Personal/Emocional': 0,
            'Propósito/Elecciones': 0,
            'Bienestar': 0
        }
        
        for q_id_str, value in responses.items():
            q_id = int(q_id_str)
            area = question_to_area.get(q_id)
            
            if area:
                # Sí = 1, No = 0
                area_scores[area] += int(value)
        
        # Calcular puntaje general (suma de todas las áreas: 0-20)
        overall_score = sum(area_scores.values())
        
        # Calcular porcentaje para la cabecera (overall_score / 20 * 100)
        overall_percentage = round((overall_score / 20) * 100, 1)
        
        # Generar texto de resultado
        result_text = generar_texto_resultado_testpersonal(overall_score, area_scores)
        
        logger.info(f"✅ TESTPERSONAL DEMO: Puntaje calculado: {overall_score}/20 ({overall_percentage}%)")
        return overall_score, overall_percentage, result_text, area_scores
        
    except Exception as e:
        logger.error(f"❌ TESTPERSONAL DEMO: Error calculando puntaje: {e}")
        return 0, 0, "Error calculando resultados", {}


def generar_texto_resultado_testpersonal(overall_score, area_scores):
    """
    Genera el texto de resultado para TestPersonal.
    Mayor puntaje = Mayor necesidad de coaching
    
    La lógica evalúa:
    - Si hay 3 o más afirmaciones en cualquier área → muestra mensaje de punto importante
    - Si hay 8 o más afirmaciones en total → muestra mensaje de momento para coaching
    - Siempre muestra el mensaje final motivacional
    
    Args:
        overall_score: Puntaje general (0-20)
        area_scores: Dict con puntajes por área (0-5 cada una)
        
    Returns:
        str: Texto descriptivo del resultado
    """
    descripcion_parts = []
    
    # Verificar si hay algún área con 3 o más afirmaciones
    areas_con_3_o_mas = []
    for area, puntaje in area_scores.items():
        if puntaje >= 3:
            areas_con_3_o_mas.append(area)
    
    # Mensaje si hay 3 o más en cualquier área
    if areas_con_3_o_mas:
        descripcion_parts.append("💡 Hay un punto importante en tu vida donde el coaching podría ayudarte a generar claridad, tomar decisiones o re-conectarte contigo misma/o.")
    
    # Mensaje si hay 8 o más en total
    if overall_score >= 8:
        if descripcion_parts:
            descripcion_parts.append("\n\n")
        descripcion_parts.append("🔥 Es un buen momento para iniciar un proceso de coaching. No porque algo esté mal… Sino porque estás lista/o para algo mejor.")
    
    # Mensaje final motivacional (siempre se muestra)
    if descripcion_parts:
        descripcion_parts.append("\n\n")
    
    descripcion_parts.append("✳️ El coaching no es para cuando todo está mal.")
    descripcion_parts.append("\nEs para cuando estás lista para dejar de ir en automático y empezar a diseñar tu vida con intención.")
    descripcion_parts.append("\n\n🌱 Si quieres avanzar con claridad, energía y propósito… el coaching es una puerta.")
    
    return "".join(descripcion_parts)


def obtener_color_area(puntaje):
    """
    Determina el color según el puntaje del área.
    
    Args:
        puntaje: Puntaje del área (0-5)
        
    Returns:
        str: Color representativo
    """
    if puntaje <= 1:
        return '#10b981'  # Verde - área fuerte
    elif puntaje == 2:
        return '#f59e0b'  # Amarillo - área de atención
    else:
        return '#ef4444'  # Rojo - área prioritaria para coaching (3 o más)


def obtener_interpretacion_area(area, puntaje):
    """
    Genera interpretación específica por área.
    
    Args:
        area: Nombre del área
        puntaje: Puntaje del área (0-5)
        
    Returns:
        str: Interpretación personalizada
    """
    interpretaciones = {
        'Profesional': {
            'bajo': 'Tienes claridad y confianza en tu desarrollo profesional.',
            'medio': 'Hay aspectos de tu carrera que podrían beneficiarse de mayor claridad.',
            'alto': 'Tu desarrollo profesional necesita atención prioritaria. El coaching puede ayudarte a encontrar tu camino.'
        },
        'Personal/Emocional': {
            'bajo': 'Cuentas con buena autoestima y gestión emocional.',
            'medio': 'Hay oportunidades para fortalecer tu confianza y bienestar emocional.',
            'alto': 'Tu bienestar emocional requiere atención. Es momento de priorizarte y trabajar en tu autoconfianza.'
        },
        'Propósito/Elecciones': {
            'bajo': 'Te sientes conectado/a con tu propósito y dirección en la vida.',
            'medio': 'Podrías beneficiarte de mayor claridad sobre tu propósito y decisiones importantes.',
            'alto': 'Necesitas reconectar con tu propósito y encontrar sentido en lo que haces. El coaching puede guiarte.'
        },
        'Bienestar': {
            'bajo': 'Mantienes buenos hábitos y equilibrio en tu vida.',
            'medio': 'Hay aspectos de tu bienestar que necesitan más atención y cuidado.',
            'alto': 'Tu energía y bienestar están comprometidos. Es urgente que te priorices y recuperes tu equilibrio.'
        }
    }
    
    # Determinar nivel basado en puntaje
    if puntaje <= 1:
        nivel = 'bajo'
    elif puntaje == 2:
        nivel = 'medio'
    else:
        nivel = 'alto'
    
    return interpretaciones.get(area, {}).get(nivel, 'Área a evaluar.')
