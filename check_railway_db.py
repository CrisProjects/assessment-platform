#!/usr/bin/env python3
"""
Script de diagnóstico de base de datos para Railway
Ejecutar después de cada deploy para verificar persistencia
"""
import os
import sys

print("=" * 70)
print("🔍 DIAGNÓSTICO DE BASE DE DATOS - RAILWAY")
print("=" * 70)

# Verificar variables de entorno
print("\n📋 VARIABLES DE ENTORNO:")
print("-" * 70)

database_url = os.environ.get('DATABASE_URL')
if database_url:
    if '@' in database_url:
        parts = database_url.split('@')
        db_host = parts[1] if len(parts) > 1 else 'unknown'
        print(f"✅ DATABASE_URL está configurada")
        print(f"   Host: {db_host}")
        
        if 'postgresql' in database_url or 'postgres' in database_url:
            print(f"   Tipo: PostgreSQL ✅ (Persistente)")
        else:
            print(f"   Tipo: {database_url.split(':')[0]} ⚠️")
    else:
        print(f"✅ DATABASE_URL: {database_url}")
else:
    print("❌ DATABASE_URL NO está configurada")
    print("   ⚠️  USANDO SQLite (datos se borran en cada deploy)")

print(f"\n   RAILWAY_ENVIRONMENT: {os.environ.get('RAILWAY_ENVIRONMENT', 'No configurado')}")
print(f"   FLASK_ENV: {os.environ.get('FLASK_ENV', 'No configurado')}")
print(f"   PORT: {os.environ.get('PORT', 'No configurado')}")

try:
    from app import app, db, User, Assessment, AssessmentResult, Response
    
    with app.app_context():
        user_count = User.query.count()
        print(f"\n✅ Conexión exitosa a base de datos")
        print(f"   Total usuarios: {user_count}")
        
        print("\n📊 RESUMEN:")
        print("-" * 70)
        
        db_type = "PostgreSQL ✅" if database_url and 'postgres' in database_url else "SQLite ⚠️"
        print(f"   Tipo de base de datos: {db_type}")
        print(f"   Total usuarios: {User.query.count()}")
        print(f"   Total evaluaciones: {Assessment.query.count()}")
        print(f"   Total resultados: {AssessmentResult.query.count()}")
        
        if not database_url or 'sqlite' in str(database_url).lower():
            print("\n⚠️  ADVERTENCIA: Estás usando SQLite")
            print("⚠️  Los datos se BORRARÁN en cada deploy")
            print("⚠️  Necesitas agregar PostgreSQL a Railway")
        else:
            print("\n✅ Configuración correcta - Datos persistirán")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    sys.exit(1)
