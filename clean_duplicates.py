#!/usr/bin/env python3
"""
Script para analizar y limpiar duplicados en assessment_result
"""
import os
import sys
from datetime import datetime
from sqlalchemy import func

# Agregar el directorio actual al path para importar el app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importar la aplicación Flask y modelos
from app import app, db, User, Assessment, AssessmentResult

def main():
    with app.app_context():
        print("🚀 Iniciando análisis y limpieza de duplicados...")
        
        # Buscar duplicados
        print("🔍 Buscando duplicados...")
        duplicates = db.session.query(
            AssessmentResult.user_id,
            AssessmentResult.assessment_id,
            func.count(AssessmentResult.id).label('count')
        ).group_by(
            AssessmentResult.user_id,
            AssessmentResult.assessment_id
        ).having(func.count(AssessmentResult.id) > 1).all()
        
        if not duplicates:
            print("✅ No se encontraron duplicados")
            return
        
        print(f"⚠️  Encontrados {len(duplicates)} casos de duplicación")
        
        total_deleted = 0
        
        for user_id, assessment_id, count in duplicates:
            user = db.session.get(User, user_id)
            assessment = db.session.get(Assessment, assessment_id)
            
            print(f"\n🔧 Procesando: {user.username} - {assessment.title}")
            print(f"   📊 {count} resultados encontrados")
            
            # Obtener todos los resultados ordenados por fecha (más reciente primero)
            all_results = AssessmentResult.query.filter_by(
                user_id=user_id,
                assessment_id=assessment_id
            ).order_by(AssessmentResult.completed_at.desc()).all()
            
            if len(all_results) <= 1:
                continue
                
            # Mantener el más reciente
            keep_result = all_results[0]
            delete_results = all_results[1:]
            
            print(f"   ✅ Manteniendo: ID {keep_result.id} (Fecha: {keep_result.completed_at})")
            print(f"   🗑️  Eliminando {len(delete_results)} duplicados:")
            
            for result in delete_results:
                print(f"      - ID: {result.id}, Fecha: {result.completed_at}")
                db.session.delete(result)
                total_deleted += 1
        
        if total_deleted > 0:
            try:
                print(f"\n💾 Guardando cambios... ({total_deleted} registros a eliminar)")
                db.session.commit()
                print("✅ LIMPIEZA COMPLETADA exitosamente")
                
                # Verificar que no queden duplicados
                remaining_duplicates = db.session.query(
                    AssessmentResult.user_id,
                    AssessmentResult.assessment_id,
                    func.count(AssessmentResult.id).label('count')
                ).group_by(
                    AssessmentResult.user_id,
                    AssessmentResult.assessment_id
                ).having(func.count(AssessmentResult.id) > 1).all()
                
                if remaining_duplicates:
                    print(f"⚠️  Aún quedan {len(remaining_duplicates)} duplicados")
                else:
                    print("🎉 Base de datos completamente limpia - No quedan duplicados")
                    
            except Exception as e:
                print(f"❌ Error guardando cambios: {e}")
                db.session.rollback()
        else:
            print("ℹ️  No hay cambios que guardar")

if __name__ == "__main__":
    main()
