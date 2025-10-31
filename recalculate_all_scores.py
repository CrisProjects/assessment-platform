"""
Script para recalcular TODOS los scores de evaluaciones existentes con las nuevas fórmulas corregidas
"""
import os
from sqlalchemy import create_engine, text

# Railway Database URL
RAILWAY_DATABASE_URL = 'postgresql://postgres:JRsYnJTgjwUWwmsWqxBagMfzSecpbvWM@centerbeam.proxy.rlwy.net:37841/railway'

def recalculate_all_scores():
    """Recalcula todos los scores de todas las evaluaciones con fórmulas corregidas"""
    engine = create_engine(RAILWAY_DATABASE_URL)
    
    with engine.connect() as conn:
        # Obtener todos los resultados de evaluaciones
        result = conn.execute(text('''
            SELECT 
                ar.id,
                ar.assessment_id,
                ar.user_id,
                u.full_name,
                a.title,
                ar.score as old_score
            FROM assessment_result ar
            JOIN "user" u ON u.id = ar.user_id
            JOIN assessment a ON a.id = ar.assessment_id
            ORDER BY ar.assessment_id, ar.id
        '''))
        
        all_results = result.fetchall()
        
        print('=' * 80)
        print(f'🔄 RECALCULANDO {len(all_results)} EVALUACIONES')
        print('=' * 80)
        print()
        
        updated_by_assessment = {}
        
        for assessment_result in all_results:
            result_id = assessment_result[0]
            assessment_id = assessment_result[1]
            user_id = assessment_result[2]
            full_name = assessment_result[3]
            assessment_title = assessment_result[4]
            old_score = assessment_result[5]
            
            # Calcular nuevo score (suma de todas las respuestas)
            result = conn.execute(text('''
                SELECT SUM(selected_option) as new_score
                FROM response
                WHERE assessment_result_id = :result_id
            '''), {'result_id': result_id})
            
            new_score_row = result.fetchone()
            new_score = new_score_row[0] if new_score_row[0] else 0
            
            # Inicializar contador para este assessment_id si no existe
            if assessment_id not in updated_by_assessment:
                updated_by_assessment[assessment_id] = {
                    'title': assessment_title,
                    'updated': 0,
                    'unchanged': 0
                }
            
            if old_score != new_score:
                # Actualizar el score
                conn.execute(text('''
                    UPDATE assessment_result
                    SET score = :new_score
                    WHERE id = :result_id
                '''), {'new_score': new_score, 'result_id': result_id})
                
                conn.commit()
                
                print(f'✅ {assessment_title}')
                print(f'   Usuario: {full_name}')
                print(f'   Score: {old_score} → {new_score} (Δ {new_score - old_score:+.1f})')
                print()
                
                updated_by_assessment[assessment_id]['updated'] += 1
            else:
                updated_by_assessment[assessment_id]['unchanged'] += 1
        
        print('-' * 80)
        print(f'📊 RESUMEN POR EVALUACIÓN:')
        print('-' * 80)
        
        total_updated = 0
        total_unchanged = 0
        
        for assessment_id, stats in sorted(updated_by_assessment.items()):
            print(f'\n{stats["title"]}:')
            print(f'   ✅ Actualizadas: {stats["updated"]}')
            print(f'   ⏭️  Sin cambios: {stats["unchanged"]}')
            
            total_updated += stats['updated']
            total_unchanged += stats['unchanged']
        
        print()
        print('=' * 80)
        print(f'📊 RESUMEN GLOBAL:')
        print(f'   Total evaluaciones: {len(all_results)}')
        print(f'   Actualizadas: {total_updated}')
        print(f'   Sin cambios: {total_unchanged}')
        print('=' * 80)
        print('✅ RECÁLCULO COMPLETADO')

if __name__ == '__main__':
    recalculate_all_scores()
