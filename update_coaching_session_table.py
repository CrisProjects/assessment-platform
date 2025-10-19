#!/usr/bin/env python3
"""
Script para actualizar la tabla coaching_session con los nuevos campos para gestión de citas
"""

import sqlite3
import os
from datetime import datetime

def update_coaching_session_table():
    """Agregar nuevos campos a la tabla coaching_session"""
    
    db_path = 'instance/assessments.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Base de datos no encontrada en: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔄 Actualizando tabla coaching_session...")
        
        # Lista de nuevos campos a agregar
        new_fields = [
            ("notes", "TEXT"),
            ("session_type", "VARCHAR(50) DEFAULT 'coaching'"),
            ("activity_type", "VARCHAR(50)"),
            ("activity_title", "VARCHAR(200)"),
            ("activity_description", "TEXT"),
            ("is_recurring", "BOOLEAN DEFAULT 0"),
            ("created_by_coach", "BOOLEAN DEFAULT 0"),
            ("notification_message", "TEXT")
        ]
        
        # Verificar qué campos ya existen
        cursor.execute("PRAGMA table_info(coaching_session)")
        existing_columns = [column[1] for column in cursor.fetchall()]
        print(f"📋 Columnas existentes: {existing_columns}")
        
        # Agregar campos faltantes
        for field_name, field_type in new_fields:
            if field_name not in existing_columns:
                try:
                    alter_sql = f"ALTER TABLE coaching_session ADD COLUMN {field_name} {field_type}"
                    cursor.execute(alter_sql)
                    print(f"✅ Campo agregado: {field_name} ({field_type})")
                except sqlite3.Error as e:
                    print(f"⚠️ Error agregando campo {field_name}: {e}")
            else:
                print(f"ℹ️ Campo ya existe: {field_name}")
        
        # También necesitamos hacer coachee_id nullable si no lo es
        try:
            # Verificar la estructura actual
            cursor.execute("PRAGMA table_info(coaching_session)")
            columns_info = cursor.fetchall()
            
            coachee_id_info = None
            for col in columns_info:
                if col[1] == 'coachee_id':
                    coachee_id_info = col
                    break
            
            if coachee_id_info and coachee_id_info[3] == 1:  # NOT NULL
                print("🔄 Haciendo coachee_id nullable para actividades del coach...")
                
                # Obtener todas las columnas y tipos
                all_columns = []
                for col in columns_info:
                    col_name = col[1]
                    col_type = col[2]
                    is_pk = col[5] == 1
                    
                    if col_name == 'coachee_id':
                        # Hacer nullable
                        all_columns.append(f"{col_name} {col_type}")
                    elif is_pk:
                        all_columns.append(f"{col_name} {col_type} PRIMARY KEY")
                    else:
                        not_null = " NOT NULL" if col[3] == 1 else ""
                        default = f" DEFAULT {col[4]}" if col[4] is not None else ""
                        all_columns.append(f"{col_name} {col_type}{not_null}{default}")
                
                # Crear tabla temporal
                temp_table_sql = f"""
                CREATE TABLE coaching_session_new (
                    {', '.join(all_columns)}
                )
                """
                
                cursor.execute(temp_table_sql)
                
                # Copiar datos
                cursor.execute("""
                INSERT INTO coaching_session_new 
                SELECT * FROM coaching_session
                """)
                
                # Eliminar tabla vieja y renombrar
                cursor.execute("DROP TABLE coaching_session")
                cursor.execute("ALTER TABLE coaching_session_new RENAME TO coaching_session")
                
                print("✅ coachee_id ahora es nullable")
        
        except sqlite3.Error as e:
            print(f"⚠️ Error modificando coachee_id: {e}")
        
        # Crear índices para los nuevos campos
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_coaching_session_type ON coaching_session(session_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_coaching_activity_type ON coaching_session(activity_type)")
            print("✅ Índices creados")
        except sqlite3.Error as e:
            print(f"⚠️ Error creando índices: {e}")
        
        conn.commit()
        print("✅ Tabla coaching_session actualizada exitosamente")
        
        # Verificar la estructura final
        cursor.execute("PRAGMA table_info(coaching_session)")
        final_columns = cursor.fetchall()
        print("\n📋 Estructura final de la tabla:")
        for col in final_columns:
            nullable = "NULL" if col[3] == 0 else "NOT NULL"
            default = f" DEFAULT({col[4]})" if col[4] is not None else ""
            print(f"   {col[1]} {col[2]} {nullable}{default}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error actualizando base de datos: {e}")
        return False

if __name__ == "__main__":
    print("🗄️ Script de actualización de tabla coaching_session")
    print("=" * 50)
    
    success = update_coaching_session_table()
    
    if success:
        print("\n🎉 Actualización completada exitosamente")
        print("✅ La tabla coaching_session ahora soporta:")
        print("   - Actividades autoagendadas del coach")
        print("   - Citas directas creadas por el coach")  
        print("   - Campos adicionales para gestión avanzada")
    else:
        print("\n❌ La actualización falló")
        print("   Revisa los mensajes de error arriba")
