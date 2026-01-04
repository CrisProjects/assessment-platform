#!/usr/bin/env python3
"""
Script para migrar documentos en PRODUCCIÓN
Actualiza Content URLs y verifica/corrige rutas de DocumentFile

IMPORTANTE: Ejecutar este script en Railway CLI:
railway run python migrate_production_documents.py

O desde la terminal de Railway en el dashboard
"""

import os
import sys
from datetime import datetime

# Configurar el ambiente antes de importar app
os.environ['FLASK_ENV'] = 'production'

from app import app, db, Content, Document, DocumentFile, USE_S3

def fix_file_paths():
    """Corrige las rutas de archivos en producción"""
    print("\n🔧 Verificando y corrigiendo rutas de archivos...\n")
    
    files = DocumentFile.query.all()
    fixed_count = 0
    
    for doc_file in files:
        old_path = doc_file.file_path
        
        # Si es URL de S3, no hacer nada
        if old_path and old_path.startswith('https://'):
            print(f"✅ Archivo {doc_file.id}: Ya usa S3")
            continue
        
        # Si la ruta no es absoluta o no comienza con /app (Railway)
        if old_path and not old_path.startswith('/app/'):
            # Extraer solo el nombre del archivo
            filename = os.path.basename(old_path)
            
            # Construir nueva ruta absoluta para producción
            if USE_S3:
                print(f"⚠️  Archivo {doc_file.id}: Debería estar en S3 pero tiene ruta local: {old_path}")
                print(f"   👉 Manteniendo ruta actual, considerar re-subir a S3")
            else:
                new_path = os.path.abspath(os.path.join('/app/uploads/documents', filename))
                
                if new_path != old_path:
                    print(f"🔄 Archivo {doc_file.id}:")
                    print(f"   Antigua: {old_path}")
                    print(f"   Nueva:   {new_path}")
                    
                    doc_file.file_path = new_path
                    fixed_count += 1
        else:
            print(f"✅ Archivo {doc_file.id}: Ruta correcta")
    
    if fixed_count > 0:
        db.session.commit()
        print(f"\n✅ Corregidas {fixed_count} rutas de archivo")
    else:
        print(f"\n✅ Todas las rutas están correctas")
    
    return fixed_count

def migrate_content_urls():
    """Migra URLs de Content de endpoints viejos a nuevos"""
    print("\n🔍 Buscando contenidos con URLs antiguas...\n")
    
    # Buscar todos los Content de tipo documento con URL antigua
    old_contents = Content.query.filter(
        Content.content_type == 'document',
        Content.content_url.like('%/api/coach/documents/%/view%')
    ).all()
    
    if not old_contents:
        print("✅ No hay contenidos con URLs antiguas")
        return 0
    
    print(f"📊 Encontrados {len(old_contents)} contenidos para migrar\n")
    
    migrated = 0
    skipped = 0
    errors = 0
    
    for content in old_contents:
        try:
            old_url = content.content_url
            
            # Extraer document_id de la URL antigua
            import re
            match = re.search(r'/api/coach/documents/(\d+)/view', old_url)
            
            if not match:
                print(f"⏭️  Content {content.id}: URL no coincide con patrón antiguo: {old_url}")
                skipped += 1
                continue
            
            document_id = int(match.group(1))
            
            # Buscar el DocumentFile correspondiente
            doc_file = DocumentFile.query.filter_by(document_id=document_id).first()
            
            if not doc_file:
                print(f"❌ Content {content.id}: No se encontró DocumentFile para documento {document_id}")
                errors += 1
                continue
            
            # Construir nueva URL
            new_url = f"/api/coachee/documents/{document_id}/files/{doc_file.id}/preview"
            
            # Actualizar
            content.content_url = new_url
            
            print(f"✅ Content {content.id}:")
            print(f"   Documento: {document_id}")
            print(f"   Antigua: {old_url}")
            print(f"   Nueva:   {new_url}")
            print()
            
            migrated += 1
            
        except Exception as e:
            print(f"❌ Error migrando Content {content.id}: {str(e)}")
            errors += 1
    
    # Commit de cambios
    if migrated > 0:
        db.session.commit()
        print(f"\n{'='*60}")
        print(f"✅ Migración completada exitosamente!")
        print(f"📊 Migrados: {migrated}, ⏭️  Omitidos: {skipped}, ❌ Errores: {errors}")
        print(f"{'='*60}\n")
    else:
        print("\n⚠️  No se realizaron cambios")
    
    return migrated

def verify_documents():
    """Verifica el estado de todos los documentos"""
    print("\n📋 VERIFICACIÓN DE DOCUMENTOS\n")
    print("="*60)
    
    documents = Document.query.filter_by(is_active=True).all()
    print(f"\n📁 Total documentos activos: {len(documents)}\n")
    
    for doc in documents:
        print(f"Documento #{doc.id}: {doc.title}")
        print(f"  Coach: {doc.coach_id} → Coachee: {doc.coachee_id}")
        print(f"  Creado: {doc.created_at}")
        
        # Buscar archivo
        doc_file = DocumentFile.query.filter_by(document_id=doc.id).first()
        if doc_file:
            print(f"  📄 Archivo: {doc_file.original_filename}")
            print(f"     Ruta: {doc_file.file_path}")
            
            # Verificar si existe
            if USE_S3:
                if doc_file.file_path.startswith('https://'):
                    print(f"     ✅ Almacenado en S3")
                else:
                    print(f"     ⚠️  Debería estar en S3 pero tiene ruta local")
            else:
                if os.path.exists(doc_file.file_path):
                    print(f"     ✅ Archivo existe en servidor")
                else:
                    print(f"     ❌ ARCHIVO NO ENCONTRADO")
        else:
            print(f"  ❌ Sin archivo asociado")
        
        # Buscar Content asociado
        content = Content.query.filter_by(
            content_type='document'
        ).filter(
            Content.content_url.contains(f'/documents/{doc.id}/')
        ).first()
        
        if content:
            print(f"  📋 Content #{content.id}: {content.content_url}")
        else:
            print(f"  ⚠️  Sin Content asociado")
        
        print()

def main():
    """Función principal"""
    with app.app_context():
        print("\n" + "="*60)
        print("🚀 MIGRACIÓN DE DOCUMENTOS EN PRODUCCIÓN")
        print("="*60)
        print(f"\n⏰ Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🌍 Ambiente: {os.environ.get('FLASK_ENV', 'unknown')}")
        print(f"☁️  Usando S3: {USE_S3}")
        
        # Verificar estado actual
        verify_documents()
        
        # Confirmar ejecución
        print("\n" + "="*60)
        print("⚠️  ATENCIÓN: Este script modificará la base de datos")
        print("="*60)
        response = input("\n¿Deseas continuar? (escribe 'si' para confirmar): ")
        
        if response.lower() != 'si':
            print("\n❌ Migración cancelada por el usuario")
            sys.exit(0)
        
        # Paso 1: Corregir rutas de archivos
        print("\n" + "="*60)
        print("PASO 1: CORRECCIÓN DE RUTAS DE ARCHIVO")
        print("="*60)
        fixed_paths = fix_file_paths()
        
        # Paso 2: Migrar URLs de Content
        print("\n" + "="*60)
        print("PASO 2: MIGRACIÓN DE URLs DE CONTENT")
        print("="*60)
        migrated_contents = migrate_content_urls()
        
        # Verificación final
        print("\n" + "="*60)
        print("VERIFICACIÓN FINAL")
        print("="*60)
        verify_documents()
        
        print("\n" + "="*60)
        print("✅ PROCESO COMPLETADO")
        print("="*60)
        print(f"\n📊 Resumen:")
        print(f"  - Rutas corregidas: {fixed_paths}")
        print(f"  - Contents migrados: {migrated_contents}")
        print(f"\n⏰ Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

if __name__ == '__main__':
    main()
