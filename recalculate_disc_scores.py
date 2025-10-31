"""
Script para recalcular scores DISC existentes con la nueva fórmula corregida
"""
import os
from sqlalchemy import create_engine, text

# Railway Database URL
RAILWAY_DATABASE_URL = 'postgresql://postgres:JRsYnJTgjwUWwmsWqxBagMfzSecpbvWM@centerbeam.proxy.rlwy.net:37841/railway'

def recalculate_disc_scores():
    """Recalcula todos los scores DISC con la fórmula corregida"""
    engine = create_engine(RAILWAY_DATABASE_URL)
    
    with engine.connect() as conn:
        # Obtener todos los resultados DISC
        result = conn.execute(text('''
            SELECT 
                ar.id,
                ar.user_id,
                u.full_name,
                ar.score as old_score
            FROM assessment_result ar
            JOIN "user" u ON u.id = ar.user_id
            WHERE ar.assessment_id = 2
            ORDER BY ar.id
        '''))
        
        disc_results = result.fetchall()
        
        print('=' * 80)
        print(f'🔄 RECALCULANDO {len(disc_results)} EVALUACIONES DISC')
        print('=' * 80)
        print()
        
        updated_count = 0
        
        for disc_result in disc_results:
            result_id = disc_result[0]
            user_id = disc_result[1]
            full_name = disc_result[2]
            old_score = disc_result[3]
            
            # Calcular nuevo score (suma de todas las respuestas)
            result = conn.execute(text('''
                SELECT SUM(selected_option) as new_score
                FROM response
                WHERE assessment_result_id = :result_id
            '''), {'result_id': result_id})
            
            new_score_row = result.fetchone()
            new_score = new_score_row[0] if new_score_row[0] else 0
            
            if old_score != new_score:
                # Actualizar el score
                conn.execute(text('''
                    UPDATE assessment_result
                    SET score = :new_score
                    WHERE id = :result_id
                '''), {'new_score': new_score, 'result_id': result_id})
                
                conn.commit()
                
                print(f'✅ Usuario: {full_name}')
                print(f'   Score: {old_score} → {new_score}')
                print(f'   Diferencia: {old_score - new_score:+.1f}')
                print()
                
                updated_count += 1
            else:
                print(f'⏭️  Usuario: {full_name} - Score ya correcto ({old_score})')
        
        print('-' * 80)
        print(f'📊 RESUMEN:')
        print(f'   Total evaluaciones: {len(disc_results)}')
        print(f'   Actualizadas: {updated_count}')
        print(f'   Sin cambios: {len(disc_results) - updated_count}')
        print('=' * 80)
        print('✅ RECÁLCULO COMPLETADO')

if __name__ == '__main__':
    recalculate_disc_scores()
