#!/usr/bin/env python3
"""
Script para agregar el campo avatar_url a la tabla user en PostgreSQL
"""

import os
import psycopg2

# Configuración de la base de datos
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:JRsYnJTgjwUWwmsWqxBagMfzSecpbvWM@centerbeam.proxy.rlwy.net:37841/railway')

def add_avatar_url_field():
    """Agregar campo avatar_url a la tabla user"""
    try:
        # Conectar a PostgreSQL
        print("🔌 Conectando a PostgreSQL Railway...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("\n" + "="*80)
        print("📋 AGREGANDO CAMPO avatar_url A LA TABLA user")
        print("="*80)
        
        # Verificar si el campo ya existe
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='user' AND column_name='avatar_url'
        """)
        
        existing = cursor.fetchone()
        
        if existing:
            print("\n⚠️  El campo 'avatar_url' ya existe en la tabla 'user'")
            print("No se requiere migración")
        else:
            print("\n✅ Agregando campo 'avatar_url' a la tabla 'user'...")
            
            # Agregar el campo
            cursor.execute("""
                ALTER TABLE "user" 
                ADD COLUMN avatar_url VARCHAR(500)
            """)
            
            conn.commit()
            print("✅ Campo 'avatar_url' agregado exitosamente")
            
            # Verificar que se agregó correctamente
            cursor.execute("""
                SELECT column_name, data_type, character_maximum_length
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='avatar_url'
            """)
            
            result = cursor.fetchone()
            if result:
                print(f"\n📊 Información del campo:")
                print(f"   Nombre: {result[0]}")
                print(f"   Tipo: {result[1]}")
                print(f"   Longitud máxima: {result[2]}")
        
        # Cerrar conexión
        cursor.close()
        conn.close()
        
        print("\n✅ Migración completada exitosamente")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    add_avatar_url_field()
