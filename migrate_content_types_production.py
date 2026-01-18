#!/usr/bin/env python3
"""
Script para migrar tipos de contenido en producción.
Ejecutar en Railway CLI o directamente en la consola de Railway.
"""

from app import app, db, Content
from sqlalchemy import func

def migrate_content_types():
    with app.app_context():
        print("🔄 Iniciando migración de tipos de contenido...")
        
        # Mostrar estado actual
        print("\n📊 Estado ANTES de la migración:")
        types_before = db.session.query(Content.content_type, func.count(Content.id)).group_by(Content.content_type).all()
        for content_type, count in types_before:
            print(f"  {content_type}: {count} items")
        
        # Actualizar 'youtube' e 'instagram' a 'video'
        updated_youtube = Content.query.filter_by(content_type='youtube').update({'content_type': 'video'})
        updated_instagram = Content.query.filter_by(content_type='instagram').update({'content_type': 'video'})
        
        db.session.commit()
        
        print(f"\n✅ Actualizado {updated_youtube} registros de 'youtube' a 'video'")
        print(f"✅ Actualizado {updated_instagram} registros de 'instagram' a 'video'")
        
        # Mostrar estado final
        print("\n📊 Estado DESPUÉS de la migración:")
        types_after = db.session.query(Content.content_type, func.count(Content.id)).group_by(Content.content_type).all()
        for content_type, count in types_after:
            print(f"  {content_type}: {count} items")
        
        print("\n✨ Migración completada exitosamente!")

if __name__ == '__main__':
    migrate_content_types()
