/**
 * Assessment Platform - Recommendations Presentation
 * Funciones comunes para la presentación de recomendaciones en dashboards
 * Este archivo centraliza la lógica de presentación para evitar duplicación de código
 */

/**
        html += `
            <div class="recommendation-category mb-4 ${categoryClass}" data-category="${key}">
                <div class="category-header">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="d-flex align-items-center">
                            <i class="${category.icon} me-2"></i>
                            <div>
                                <h6 class="category-title mb-0" style="color: white !important;">${category.title}</h6>
                                ${key === 'general' ? `<p class="category-description mb-0">${category.description}</p>` : ''}
                            </div>
                        </div>
                        <div class="recommendation-count">
                            ${category.items.length}
                        </div>
                    </div>
                </div>`ara mostrar recomendaciones categorizadas
 * @param {Array} recommendations - Array de recomendaciones del servidor
 * @returns {string} HTML formateado para mostrar las recomendaciones
 */
function generateRecommendationsHTML(recommendations) {
    console.log('🔍 generateRecommendationsHTML - Recomendaciones recibidas:', recommendations);
    
    if (!recommendations || recommendations.length === 0) return '';
    
    // Procesar y categorizar recomendaciones
    const categorizedRecs = categorizeRecommendations(recommendations);
    console.log('📊 Recomendaciones categorizadas:', categorizedRecs);
    
    let html = `
        <div class="row mb-4">
            <div class="col-12">
                <div class="unified-card">
                    <div class="unified-card-header">
                        <div class="d-flex align-items-center justify-content-between">
                            <div>
                                <h5 class="mb-0" style="color: white !important;">
                                    <i class="fas fa-lightbulb unified-icon"></i>
                                    Plan de Desarrollo Personalizado
                                </h5>
                                <div class="card-subtitle mt-2">
                                    Recomendaciones categorizadas basadas en tu evaluación
                                </div>
                            </div>
                            <div class="text-end">
                                <div class="unified-badge unified-badge-light">
                                    ${getTotalRecommendationsCount(categorizedRecs)} recomendaciones
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-md-4">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-chart-line unified-icon-sm me-2"></i>
                                    <small>Basado en tu puntuación</small>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-target unified-icon-sm me-2"></i>
                                    <small>Objetivos específicos</small>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-clock unified-icon-sm me-2"></i>
                                    <small>Plan a 90 días</small>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="unified-card-body">
                        ${generateCategorizedRecommendationsHTML(categorizedRecs)}
                    </div>
                </div>
            </div>
        </div>
    `;
    
    return html;
}

/**
 * Categoriza las recomendaciones en diferentes áreas de desarrollo
 * @param {Array} recommendations - Array de recomendaciones del servidor
 * @returns {Object} Objeto con categorías organizadas
 */
function categorizeRecommendations(recommendations) {
    console.log('🏷️ categorizeRecommendations - Entrada:', recommendations);
    
    const categories = {
        comunicacion: {
            title: 'Habilidades de Comunicación',
            icon: 'fas fa-comments',
            color: 'primary',
            items: [],
            priority: 1,
            description: 'Mejora tu capacidad para expresarte de manera clara y efectiva'
        },
        liderazgo: {
            title: 'Desarrollo de Liderazgo',
            icon: 'fas fa-crown',
            color: 'success',
            items: [],
            priority: 2,
            description: 'Fortalece tus competencias de liderazgo y dirección de equipos'
        },
        asertividad: {
            title: 'Técnicas de Asertividad',
            icon: 'fas fa-balance-scale',
            color: 'warning',
            items: [],
            priority: 3,
            description: 'Desarrolla tu capacidad para defender tus derechos respetando a otros'
        },
        emocional: {
            title: 'Inteligencia Emocional',
            icon: 'fas fa-heart',
            color: 'danger',
            items: [],
            priority: 4,
            description: 'Gestiona mejor tus emociones y las de tu entorno'
        },
        conflictos: {
            title: 'Gestión de Conflictos',
            icon: 'fas fa-handshake',
            color: 'info',
            items: [],
            priority: 5,
            description: 'Aprende a resolver conflictos de manera constructiva'
        },
        general: {
            title: 'Desarrollo General',
            icon: 'fas fa-star',
            color: 'secondary',
            items: [],
            priority: 6,
            description: 'Recomendaciones adicionales para tu crecimiento profesional'
        }
    };
    
    // Procesar cada recomendación
    recommendations.forEach(rec => {
        const recText = typeof rec === 'string' ? rec : rec.text || rec.description || '';
        const category = categorizeRecommendation(recText);
        
        if (categories[category]) {
            categories[category].items.push({
                text: recText,
                priority: getPriorityFromText(recText),
                actionItems: extractActionItems(recText)
            });
        }
    });
    
    // Filtrar categorías vacías y ordenar por prioridad
    const filteredCategories = Object.entries(categories)
        .filter(([key, category]) => category.items.length > 0)
        .sort((a, b) => a[1].priority - b[1].priority);
    
    return Object.fromEntries(filteredCategories);
}

/**
 * Categoriza una recomendación individual basada en palabras clave
 * @param {string} text - Texto de la recomendación
 * @returns {string} Nombre de la categoría
 */
function categorizeRecommendation(text) {
    const textLower = text.toLowerCase();
    
    if (textLower.includes('comunicación') || textLower.includes('expresar') || textLower.includes('hablar') || textLower.includes('escuchar')) {
        return 'comunicacion';
    } else if (textLower.includes('liderar') || textLower.includes('liderazgo') || textLower.includes('equipo') || textLower.includes('dirigir')) {
        return 'liderazgo';
    } else if (textLower.includes('asertiv') || textLower.includes('derechos') || textLower.includes('opinión') || textLower.includes('firme')) {
        return 'asertividad';
    } else if (textLower.includes('emocional') || textLower.includes('emociones') || textLower.includes('sentimientos') || textLower.includes('autocontrol')) {
        return 'emocional';
    } else if (textLower.includes('conflicto') || textLower.includes('negociación') || textLower.includes('mediación') || textLower.includes('resolver')) {
        return 'conflictos';
    } else {
        return 'general';
    }
}

/**
 * Extrae elementos de acción específicos del texto de recomendación
 * @param {string} text - Texto de la recomendación
 * @returns {Array} Array de elementos de acción extraídos
 */
function extractActionItems(text) {
    const actionWords = ['práctica', 'ejercita', 'desarrolla', 'mejora', 'fortalece', 'aprende', 'implementa'];
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    
    return sentences.filter(sentence => {
        const sentenceLower = sentence.toLowerCase();
        return actionWords.some(word => sentenceLower.includes(word));
    }).slice(0, 3); // Máximo 3 elementos de acción
}

/**
 * Obtiene la prioridad de una recomendación basada en palabras clave
 * @param {string} text - Texto de la recomendación
 * @returns {string} Nivel de prioridad: 'high', 'medium', 'low'
 */
function getPriorityFromText(text) {
    const textLower = text.toLowerCase();
    if (textLower.includes('urgente') || textLower.includes('inmediato') || textLower.includes('crítico')) {
        return 'high';
    } else if (textLower.includes('importante') || textLower.includes('recomendado') || textLower.includes('esencial')) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Cuenta el total de recomendaciones en todas las categorías
 * @param {Object} categories - Objeto con categorías de recomendaciones
 * @returns {number} Número total de recomendaciones
 */
function getTotalRecommendationsCount(categories) {
    return Object.values(categories).reduce((total, category) => total + category.items.length, 0);
}

/**
 * Genera HTML para mostrar categorías organizadas de recomendaciones
 * @param {Object} categories - Objeto con categorías de recomendaciones
 * @returns {string} HTML formateado de las categorías
 */
function generateCategorizedRecommendationsHTML(categories) {
    let html = '';
    
    Object.entries(categories).forEach(([key, category], index) => {
        // Clase especial para desarrollo general con diseño minimalista
        const categoryClass = key === 'general' ? 'general-recommendations' : `category-${key}`;
        
        html += `
            <div class="recommendation-category mb-4 ${categoryClass}" data-category="${key}">
                <div class="category-header">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="d-flex align-items-center">
                            <i class="${category.icon} me-2"></i>
                            <div>
                                <h6 class="category-title mb-0">${category.title}</h6>
                                ${key === 'general' ? `<p class="category-description mb-0">${category.description}</p>` : ''}
                            </div>
                        </div>
                        <div class="recommendation-count">
                            ${category.items.length}
                        </div>
                    </div>
                </div>
                
                <div class="recommendation-items">
                    ${generateCategoryItemsHTML(category.items, key)}
                </div>
            </div>
        `;
    });
    
    return html;
}

/**
 * Genera HTML para los elementos de una categoría de recomendaciones
 * @param {Array} items - Items de la categoría
 * @param {string} categoryKey - Clave de la categoría
 * @returns {string} HTML de los items
 */
function generateCategoryItemsHTML(items, categoryKey) {
    // Si no hay items, mostrar estado vacío para desarrollo general
    if (items.length === 0 && categoryKey === 'general') {
        return `
            <div class="empty-state">
                <i class="fas fa-lightbulb"></i>
                <h6>Sin recomendaciones específicas</h6>
                <p>Continúa con tu excelente desarrollo profesional</p>
            </div>
        `;
    }
    
    return items.map((item, itemIndex) => {
        // Usar clases minimalistas para desarrollo general
        if (categoryKey === 'general') {
            return `
                <div class="recommendation-item">
                    <p class="recommendation-text">${formatRecommendationText(item.text)}</p>
                </div>
            `;
        }
        
        // Formato estándar para otras categorías
        return `
            <div class="recommendation-item" data-priority="${item.priority}">
                <div class="recommendation-item-header">
                    <div class="recommendation-item-number category-${categoryKey}" style="color: white;">
                        ${itemIndex + 1}
                    </div>
                    <div class="recommendation-item-priority">
                        ${getPriorityIcon(item.priority)}
                        <span class="unified-badge unified-badge-${getPriorityColor(item.priority)} me-2">
                            ${item.priority.toUpperCase()}
                        </span>
                        <small class="text-muted">
                            Prioridad ${item.priority === 'high' ? 'Alta' : item.priority === 'medium' ? 'Media' : 'Baja'}
                        </small>
                    </div>
                </div>
                <div class="recommendation-item-text">
                    ${formatRecommendationText(item.text)}
                </div>
                ${item.actionItems && item.actionItems.length > 0 ? `
                    <div class="recommendation-action-items">
                        <h6 class="recommendation-action-title category-${categoryKey}">
                            <i class="fas fa-tasks unified-icon-sm"></i>
                            Acciones Sugeridas:
                        </h6>
                        <ul class="recommendation-action-list">
                            ${item.actionItems.map(action => `
                            <li>${action.trim()}</li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
        `;
    }).join('');
}

/**
 * Formatea el texto de una recomendación para mejor presentación
 * @param {string} text - Texto original de la recomendación
 * @returns {string} Texto formateado con markdown básico
 */
function formatRecommendationText(text) {
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // Negrita
        .replace(/\*(.*?)\*/g, '<em>$1</em>') // Cursiva
        .replace(/^• /gm, '<i class="fas fa-arrow-right me-2 text-primary"></i>') // Bullets
        .replace(/\n/g, '<br>'); // Saltos de línea
}

/**
 * Obtiene el icono correspondiente a la prioridad
 * @param {string} priority - Nivel de prioridad
 * @returns {string} HTML del icono
 */
function getPriorityIcon(priority) {
    const icons = {
        'high': 'fas fa-exclamation-circle',
        'medium': 'fas fa-star',
        'low': 'fas fa-circle'
    };
    return `<i class="${icons[priority] || icons.low} unified-icon-sm me-2"></i>`;
}

/**
 * Obtiene el color de badge correspondiente a la prioridad
 * @param {string} priority - Nivel de prioridad
 * @returns {string} Clase de color
 */
function getPriorityColor(priority) {
    const colors = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'light'
    };
    return colors[priority] || colors.low;
}
