#!/usr/bin/env python3
"""
Script de diagnóstico rápido para documentos en producción
Muestra el estado actual sin hacer cambios

Ejecutar en Railway: python quick_check_production_docs.py
"""

import os
from app import app, db, Content, Document, DocumentFile, USE_S3

def main():
    with app.app_context():
        print("\n" + "="*70)
        print("📊 DIAGNÓSTICO DE DOCUMENTOS EN PRODUCCIÓN")
        print("="*70)
        print(f"\n☁️  Usando S3: {USE_S3}")
        print(f"🌍 Ambiente: {os.environ.get('FLASK_ENV', 'unknown')}")
        
        # Buscar documentos con URLs antiguas
        old_urls = Content.query.filter(
            Content.content_type == 'document',
            Content.content_url.like('%/api/coach/documents/%/view%')
        ).all()
        
        new_urls = Content.query.filter(
            Content.content_type == 'document',
            Content.content_url.like('%/api/coachee/documents/%/preview%')
        ).all()
        
        print(f"\n📋 CONTENIDOS TIPO DOCUMENTO:")
        print(f"  ❌ Con URLs antiguas: {len(old_urls)}")
        print(f"  ✅ Con URLs nuevas:   {len(new_urls)}")
        
        if old_urls:
            print(f"\n⚠️  CONTENIDOS QUE NECESITAN MIGRACIÓN:\n")
            for content in old_urls:
                print(f"  Content #{content.id}: {content.title}")
                print(f"    URL: {content.content_url}")
                print(f"    Coach {content.coach_id} → Coachee {content.coachee_id}")
                print()
        
        # Verificar rutas de archivos
        print(f"\n📁 ARCHIVOS DE DOCUMENTOS:\n")
        files = DocumentFile.query.all()
        
        local_paths = 0
        s3_paths = 0
        missing = 0
        
        for doc_file in files:
            path = doc_file.file_path
            
            if path.startswith('https://'):
                s3_paths += 1
                status = "☁️  S3"
            elif path.startswith('/app/'):
                if os.path.exists(path):
                    status = "✅ Local OK"
                else:
                    status = "❌ NO EXISTE"
                    missing += 1
                local_paths += 1
            else:
                status = "⚠️  Ruta incorrecta"
                local_paths += 1
                if not os.path.exists(path):
                    missing += 1
            
            print(f"  Archivo #{doc_file.id}: {doc_file.original_filename}")
            print(f"    {status}: {path}")
            print()
        
        print(f"\n📊 RESUMEN:")
        print(f"  - Archivos en S3: {s3_paths}")
        print(f"  - Archivos locales: {local_paths}")
        print(f"  - Archivos no encontrados: {missing}")
        
        print(f"\n💡 RECOMENDACIÓN:")
        if old_urls:
            print(f"  ⚠️  Hay {len(old_urls)} contenido(s) con URLs antiguas")
            print(f"  👉 Ejecuta: python migrate_production_documents.py")
        else:
            print(f"  ✅ Todos los contenidos usan URLs nuevas")
        
        if missing > 0:
            print(f"  ⚠️  Hay {missing} archivo(s) no encontrados")
            print(f"  👉 Verifica las rutas o re-sube los archivos")
        
        print("\n" + "="*70 + "\n")

if __name__ == '__main__':
    main()
