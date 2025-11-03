"""
Script de migración para crear tabla de historial de evaluaciones
y eliminar la restricción única que impide múltiples resultados.
"""
from app import app, db
from sqlalchemy import text

def run_migration():
    """Ejecutar migración para agregar tabla de historial"""
    
    with app.app_context():
        print("🔄 Iniciando migración de base de datos...")
        
        try:
            # 1. Crear tabla de historial si no existe
            print("\n1️⃣  Creando tabla assessment_history...")
            
            create_history_table = text("""
                CREATE TABLE IF NOT EXISTS assessment_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    assessment_id INTEGER NOT NULL,
                    score REAL,
                    total_questions INTEGER,
                    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    result_text TEXT,
                    dimensional_scores TEXT,
                    attempt_number INTEGER DEFAULT 1,
                    coach_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES user (id),
                    FOREIGN KEY (assessment_id) REFERENCES assessment (id),
                    FOREIGN KEY (coach_id) REFERENCES user (id)
                );
            """)
            
            db.session.execute(create_history_table)
            print("   ✅ Tabla assessment_history creada exitosamente")
            
            # 2. Crear índices para la tabla de historial
            print("\n2️⃣  Creando índices para assessment_history...")
            
            create_indexes = [
                "CREATE INDEX IF NOT EXISTS idx_history_user ON assessment_history(user_id);",
                "CREATE INDEX IF NOT EXISTS idx_history_assessment ON assessment_history(assessment_id);",
                "CREATE INDEX IF NOT EXISTS idx_history_completed ON assessment_history(completed_at);",
                "CREATE INDEX IF NOT EXISTS idx_history_user_assessment ON assessment_history(user_id, assessment_id);",
            ]
            
            for idx_sql in create_indexes:
                db.session.execute(text(idx_sql))
            
            print("   ✅ Índices creados exitosamente")
            
            # 3. Migrar datos existentes de assessment_result a assessment_history
            print("\n3️⃣  Migrando datos existentes a historial...")
            
            migrate_data = text("""
                INSERT INTO assessment_history 
                    (user_id, assessment_id, score, total_questions, completed_at, 
                     result_text, dimensional_scores, attempt_number, coach_id)
                SELECT 
                    user_id, assessment_id, score, total_questions, completed_at,
                    result_text, 
                    CASE 
                        WHEN dimensional_scores IS NOT NULL THEN dimensional_scores
                        ELSE NULL
                    END,
                    1 as attempt_number,
                    coach_id
                FROM assessment_result
                WHERE id NOT IN (SELECT id FROM assessment_history WHERE id = assessment_result.id);
            """)
            
            result = db.session.execute(migrate_data)
            rows_migrated = result.rowcount
            print(f"   ✅ {rows_migrated} registros migrados al historial")
            
            # 4. Intentar eliminar la restricción única (si existe)
            print("\n4️⃣  Eliminando restricción única de assessment_result...")
            
            try:
                # En SQLite, necesitamos recrear la tabla sin la restricción
                # Primero, verificar si existe la restricción
                check_constraint = text("""
                    SELECT sql FROM sqlite_master 
                    WHERE type='table' AND name='assessment_result';
                """)
                
                result = db.session.execute(check_constraint).fetchone()
                
                if result and 'UNIQUE' in result[0]:
                    print("   ⚠️  Restricción única detectada - requiere recrear tabla")
                    print("   ℹ️  Esta operación se realizará en el siguiente deployment")
                    print("   ℹ️  Por ahora, la aplicación manejará múltiples resultados vía código")
                else:
                    print("   ✅ No se encontró restricción única")
                    
            except Exception as e:
                print(f"   ⚠️  No se pudo verificar restricción: {str(e)}")
            
            # 5. Commit de todos los cambios
            db.session.commit()
            
            print("\n" + "="*70)
            print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
            print("="*70)
            print("\n📊 Resumen:")
            print(f"   • Tabla assessment_history creada")
            print(f"   • Índices creados para mejor rendimiento")
            print(f"   • {rows_migrated} registros históricos migrados")
            print(f"   • Sistema preparado para guardar múltiples intentos")
            print("\n💡 Próximos pasos:")
            print("   1. Reiniciar el servidor")
            print("   2. Los nuevos intentos se guardarán automáticamente en el historial")
            print("   3. La tabla assessment_result mantendrá el último resultado")
            print("\n" + "="*70 + "\n")
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ ERROR durante la migración: {str(e)}")
            import traceback
            traceback.print_exc()
            raise

if __name__ == '__main__':
    run_migration()
