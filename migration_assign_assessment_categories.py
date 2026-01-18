#!/usr/bin/env python3
"""
Migración: Asignar categorías a evaluaciones basándose en su título/contenido
"""
import os
import sys
from sqlalchemy import create_engine, text

def assign_assessment_categories():
    """Asignar categorías a evaluaciones que tienen 'Otros' o null"""
    
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("❌ ERROR: DATABASE_URL no está configurada")
        return False
    
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    # Reglas de categorización basadas en palabras clave
    category_rules = {
        'Personalidad': [
            'personalidad', 'disc', 'temperamento', 'carácter', 'mbti', 
            'estilo', 'comportamiento'
        ],
        'Liderazgo': [
            'liderazgo', 'líder', 'gestión', 'management', 'dirección',
            'supervisión', 'jefatura'
        ],
        'Inteligencia Emocional': [
            'emocional', 'emoción', 'empatía', 'autocontrol', 'inteligencia emocional',
            'eq', 'sentimientos'
        ],
        'Trabajo en Equipo': [
            'equipo', 'colaboración', 'teamwork', 'team', 'colaborativo',
            'grupal', 'cooperación'
        ],
        'Crecimiento Empresarial': [
            'empresarial', 'negocio', 'estrategia', 'marketing', 'ventas',
            'crecimiento', 'desarrollo organizacional', 'business'
        ]
    }
    
    try:
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # Obtener evaluaciones sin categoría o con 'Otros'
            result = conn.execute(text("""
                SELECT id, title, description, category
                FROM assessment
                WHERE is_active = true
                AND (category IS NULL OR category = 'Otros' OR category = '')
                ORDER BY id;
            """))
            
            assessments = result.fetchall()
            
            print("=" * 80)
            print("🔧 ASIGNANDO CATEGORÍAS A EVALUACIONES")
            print("=" * 80)
            print(f"\nEvaluaciones a procesar: {len(assessments)}\n")
            
            updated_count = 0
            
            for row in assessments:
                id, title, description, current_category = row
                
                # Buscar categoría apropiada
                new_category = None
                text_to_analyze = f"{title} {description or ''}".lower()
                
                for category, keywords in category_rules.items():
                    for keyword in keywords:
                        if keyword in text_to_analyze:
                            new_category = category
                            break
                    if new_category:
                        break
                
                # Si no se encontró categoría, dejar en 'Otros'
                if not new_category:
                    new_category = 'Otros'
                
                # Actualizar en BD
                conn.execute(text("""
                    UPDATE assessment
                    SET category = :category
                    WHERE id = :id;
                """), {'category': new_category, 'id': id})
                
                print(f"  ✅ ID {id}: '{title}'")
                print(f"     Categoría asignada: {new_category}")
                print()
                
                updated_count += 1
            
            conn.commit()
            
            print("=" * 80)
            print(f"✅ MIGRACIÓN COMPLETADA")
            print(f"   Evaluaciones actualizadas: {updated_count}")
            print("=" * 80)
            
        engine.dispose()
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == '__main__':
    print("\n")
    success = assign_assessment_categories()
    print("\n")
    sys.exit(0 if success else 1)
