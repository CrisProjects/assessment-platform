#!/usr/bin/env python3
"""
Migración: Convertir scores existentes en AssessmentHistory a porcentajes

Este script actualiza todos los registros existentes en la tabla assessment_history
para que el campo 'score' contenga porcentajes (0-100) en lugar de scores raw.
"""

from app import app, db, AssessmentHistory
from sqlalchemy import text

def migrate_scores_to_percentage():
    """Convierte todos los scores existentes a porcentajes"""
    
    print('\n' + '='*70)
    print('🔄 MIGRACIÓN: Convertir Scores a Porcentajes')
    print('='*70 + '\n')
    
    with app.app_context():
        try:
            # Obtener todos los registros de historial
            all_entries = AssessmentHistory.query.all()
            
            print(f'📊 Total de registros a actualizar: {len(all_entries)}')
            
            if len(all_entries) == 0:
                print('✅ No hay registros para actualizar')
                return
            
            print('\n' + '-'*70)
            print(f'{"ID":<8} {"SCORE RAW":<12} {"TOTAL Q":<10} {"% CALCULADO":<15} {"ESTADO"}')
            print('-'*70)
            
            updated_count = 0
            skipped_count = 0
            
            for entry in all_entries:
                # Si el total_questions existe y el score parece ser raw (no porcentaje)
                if entry.total_questions and entry.total_questions > 0:
                    # Calcular el porcentaje teórico
                    percentage = round((entry.score / entry.total_questions) * 100, 2)
                    
                    # Si el porcentaje calculado es diferente al score actual (considerando 2 decimales),
                    # entonces necesitamos actualizar
                    if abs(entry.score - percentage) > 0.01 and entry.score <= 100:
                        # Score actual parece ser raw, convertir a porcentaje
                        print(f'{entry.id:<8} {entry.score:<12.1f} {entry.total_questions:<10} {percentage:<15.2f} ✅ ACTUALIZADO')
                        
                        # Actualizar el score a porcentaje
                        entry.score = percentage
                        updated_count += 1
                    else:
                        # Ya parece ser un porcentaje (o score muy alto)
                        print(f'{entry.id:<8} {entry.score:<12.2f} {entry.total_questions:<10} {percentage:<15.2f} ⏭️  YA ES %')
                        skipped_count += 1
                else:
                    print(f'{entry.id:<8} {entry.score:<12.1f} {"N/A":<10} {"N/A":<15} ⚠️  SIN TOTAL')
                    skipped_count += 1
            
            print('-'*70)
            
            # Hacer commit de los cambios
            if updated_count > 0:
                db.session.commit()
                print(f'\n✅ Migración completada exitosamente')
                print(f'   📊 Registros actualizados: {updated_count}')
                print(f'   ⏭️  Registros omitidos: {skipped_count}')
            else:
                print(f'\n✅ No se requirieron actualizaciones')
                print(f'   ⏭️  Todos los registros ya están en formato de porcentaje')
            
            print('\n' + '='*70)
            
        except Exception as e:
            print(f'\n❌ ERROR durante la migración: {str(e)}')
            db.session.rollback()
            raise

if __name__ == '__main__':
    print('\n🚀 Iniciando migración de scores a porcentajes...\n')
    migrate_scores_to_percentage()
    print('\n✅ Proceso completado\n')
