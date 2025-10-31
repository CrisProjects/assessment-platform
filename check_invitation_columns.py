#!/usr/bin/env python3
"""
Script para verificar qué columnas tiene la tabla invitation en la base de datos
"""
import os
import sys
from app import app, db
from sqlalchemy import text, inspect

def check_invitation_columns():
    """Verificar columnas de la tabla invitation"""
    
    with app.app_context():
        try:
            # Detectar tipo de base de datos
            db_url = str(db.engine.url)
            is_postgres = 'postgresql' in db_url
            is_sqlite = 'sqlite' in db_url
            
            print(f"🔍 Base de datos: {'PostgreSQL' if is_postgres else 'SQLite' if is_sqlite else 'Desconocida'}")
            print(f"📍 URL: {db_url.split('@')[-1] if '@' in db_url else 'local'}")
            print("=" * 60)
            
            # Obtener columnas usando inspector
            inspector = inspect(db.engine)
            columns = inspector.get_columns('invitation')
            
            print(f"\n📋 COLUMNAS DE LA TABLA 'invitation' ({len(columns)} columnas):\n")
            
            for col in columns:
                col_type = str(col['type'])
                nullable = "NULL" if col['nullable'] else "NOT NULL"
                default = f" DEFAULT {col['default']}" if col.get('default') else ""
                print(f"  • {col['name']:<20} {col_type:<20} {nullable}{default}")
            
            # Columnas esperadas por el modelo
            print("\n" + "=" * 60)
            print("📌 COLUMNAS ESPERADAS POR EL MODELO:\n")
            
            expected_columns = [
                'id',
                'coach_id',
                'coachee_id',
                'email',
                'full_name',
                'token',
                'message',
                'created_at',
                'expires_at',
                'used_at',
                'is_used',
                'accepted_at',  # ← Esta puede faltar
                'status',       # ← Esta puede faltar
                # 'assessment_id' # ← Comentada en el modelo
            ]
            
            existing_cols = [col['name'] for col in columns]
            
            for expected in expected_columns:
                status = "✅ EXISTE" if expected in existing_cols else "❌ FALTA"
                print(f"  {status}  {expected}")
            
            # Verificar columnas extra en BD
            extra_cols = [col for col in existing_cols if col not in expected_columns]
            if extra_cols:
                print(f"\n⚠️  COLUMNAS EXTRA EN BD (no en modelo): {', '.join(extra_cols)}")
            
            print("\n" + "=" * 60)
            return True
            
        except Exception as e:
            print(f"❌ Error verificando tabla: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return False

if __name__ == '__main__':
    print("=" * 60)
    print("VERIFICACIÓN: Columnas de tabla invitation")
    print("=" * 60)
    
    success = check_invitation_columns()
    
    if success:
        print("\n✅ Verificación completada")
        sys.exit(0)
    else:
        print("\n❌ La verificación falló")
        sys.exit(1)
