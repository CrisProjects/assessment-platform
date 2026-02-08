#!/usr/bin/env python3
"""
Script para ejecutar migración de comunidades en Railway PostgreSQL
"""
import sys
import os

def run_migration():
    print("=" * 70)
    print("🚀 MIGRACIÓN DE COMUNIDADES PARA RAILWAY")
    print("=" * 70)
    print()
    
    # Pedir DATABASE_URL
    print("📋 PASO 1: Obtener DATABASE_URL de Railway")
    print("-" * 70)
    print("1. Ve a: https://railway.app")
    print("2. Selecciona tu proyecto 'assessment-platform'")
    print("3. Click en 'PostgreSQL' (el ícono de base de datos)")
    print("4. En la pestaña 'Variables', busca 'DATABASE_URL'")
    print("5. Click en el botón de copiar junto a DATABASE_URL")
    print()
    print("⚠️  El formato debe ser:")
    print("   postgresql://postgres:PASSWORD@HOST:PORT/railway")
    print()
    
    database_url = input("📥 Pega aquí el DATABASE_URL: ").strip()
    
    if not database_url:
        print("❌ DATABASE_URL vacío. Abortando.")
        return False
    
    if 'postgres' not in database_url:
        print("❌ DATABASE_URL no parece ser PostgreSQL. Verifica el formato.")
        return False
    
    print()
    print("✅ DATABASE_URL recibido")
    print()
    
    # Confirmar antes de proceder
    print("⚠️  ADVERTENCIA: Esta migración creará 3 nuevas tablas en Railway:")
    print("   - coach_community")
    print("   - community_membership")
    print("   - community_invitation")
    print()
    confirm = input("¿Continuar con la migración? (escribe 'si' para confirmar): ").strip().lower()
    
    if confirm != 'si':
        print("❌ Migración cancelada por el usuario.")
        return False
    
    print()
    print("🔧 EJECUTANDO MIGRACIÓN...")
    print("-" * 70)
    
    try:
        import psycopg2
    except ImportError:
        print("❌ ERROR: psycopg2 no está instalado")
        print("📦 Instalando psycopg2-binary...")
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'psycopg2-binary'])
        import psycopg2
        print("✅ psycopg2-binary instalado")
        print()
    
    # Asegurar postgresql:// prefix
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    try:
        # Conectar
        print("🔌 Conectando a Railway PostgreSQL...")
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        print("✅ Conexión exitosa")
        print()
        
        # 1. Crear tabla coach_community
        print("1️⃣  Creando tabla coach_community...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coach_community (
                id SERIAL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                description TEXT,
                image_url TEXT,
                image_type VARCHAR(20) DEFAULT 'catalog',
                creator_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                privacy VARCHAR(20) DEFAULT 'private'
            )
        """)
        print("   ✅ Tabla coach_community creada")
        
        # Índices para coach_community
        print("   📊 Creando índices...")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_coach_community_creator_id ON coach_community(creator_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_coach_community_is_active ON coach_community(is_active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_coach_community_created_at ON coach_community(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_coach_community_privacy ON coach_community(privacy)")
        print("   ✅ Índices creados")
        print()
        
        # 2. Crear tabla community_membership
        print("2️⃣  Creando tabla community_membership...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS community_membership (
                id SERIAL PRIMARY KEY,
                community_id INTEGER NOT NULL REFERENCES coach_community(id) ON DELETE CASCADE,
                coach_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
                role VARCHAR(20) DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE(community_id, coach_id)
            )
        """)
        print("   ✅ Tabla community_membership creada")
        
        # Índices para community_membership
        print("   📊 Creando índices...")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_membership_community_id ON community_membership(community_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_membership_coach_id ON community_membership(coach_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_membership_is_active ON community_membership(is_active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_community_active ON community_membership(community_id, is_active)")
        print("   ✅ Índices creados")
        print()
        
        # 3. Crear tabla community_invitation
        print("3️⃣  Creando tabla community_invitation...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS community_invitation (
                id SERIAL PRIMARY KEY,
                community_id INTEGER NOT NULL REFERENCES coach_community(id) ON DELETE CASCADE,
                inviter_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
                invitee_email VARCHAR(120) NOT NULL,
                invitee_name VARCHAR(200),
                token VARCHAR(128) UNIQUE NOT NULL,
                message TEXT,
                method VARCHAR(20) DEFAULT 'email',
                phone_number VARCHAR(20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                accepted_at TIMESTAMP,
                accepted_by_user_id INTEGER REFERENCES "user"(id),
                is_used BOOLEAN DEFAULT FALSE
            )
        """)
        print("   ✅ Tabla community_invitation creada")
        
        # Índices para community_invitation
        print("   📊 Creando índices...")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_invitation_token ON community_invitation(token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_invitation_community_id ON community_invitation(community_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_invitation_invitee_email ON community_invitation(invitee_email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_community_invitation_is_used ON community_invitation(is_used)")
        print("   ✅ Índices creados")
        print()
        
        # Commit
        conn.commit()
        print("💾 Cambios guardados en la base de datos")
        print()
        
        # Verificar
        print("🔍 VERIFICANDO TABLAS CREADAS...")
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_name LIKE '%community%' 
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        print("✅ Tablas encontradas:")
        for table in tables:
            print(f"   - {table[0]}")
        print()
        
        # Cerrar
        cursor.close()
        conn.close()
        
        print("=" * 70)
        print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
        print("=" * 70)
        print()
        print("🎉 La página coach-comunidad ya puede crear y editar comunidades")
        print("📡 Las APIs en /api/communities están listas para usarse")
        print()
        
        return True
        
    except Exception as e:
        print()
        print("=" * 70)
        print("❌ ERROR EN LA MIGRACIÓN")
        print("=" * 70)
        print(f"Error: {str(e)}")
        print()
        print("💡 Posibles soluciones:")
        print("   1. Verifica que DATABASE_URL sea correcto")
        print("   2. Verifica que tengas permisos en la base de datos")
        print("   3. Intenta ejecutar el SQL manualmente desde Railway Dashboard")
        print()
        return False

if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
