#!/usr/bin/env python3
"""
Migración: Agregar campos para métodos de invitación (Email, WhatsApp, SMS)
============================================================================

Agrega los siguientes campos a la tabla community_invitation:
- invitee_phone: Número de teléfono del invitado (para WhatsApp/SMS)
- invitation_method: Método usado ('email', 'whatsapp', 'sms')
- Hace invitee_email nullable (ya no es obligatorio si se usa phone)

Soporta SQLite y PostgreSQL.
"""

import os
import sys
from sqlalchemy import create_engine, text, inspect

def get_database_url():
    """Detecta y retorna la URL de la base de datos"""
    # Prioridad 1: Variable de entorno DATABASE_URL (Railway/producción)
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Railway usa postgres://, pero SQLAlchemy necesita postgresql://
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        print(f"✓ Usando base de datos de producción (PostgreSQL)")
        return database_url, 'postgresql'
    
    # Prioridad 2: Base de datos local SQLite
    db_path = os.path.join('instance', 'assessments.db')
    if os.path.exists(db_path):
        print(f"✓ Usando base de datos local: {db_path}")
        return f'sqlite:///{db_path}', 'sqlite'
    
    print("❌ ERROR: No se encontró ninguna base de datos")
    sys.exit(1)


def migrate_sqlite(engine):
    """Migración para SQLite"""
    print("\n📦 Iniciando migración SQLite...")
    
    with engine.connect() as conn:
        # SQLite no soporta ALTER COLUMN, hay que recrear la tabla
        print("  → Verificando tabla community_invitation...")
        
        # Verificar si los campos ya existen
        inspector = inspect(engine)
        columns = [col['name'] for col in inspector.get_columns('community_invitation')]
        
        if 'invitee_phone' in columns and 'invitation_method' in columns:
            print("  ✓ Los campos ya existen, saltando migración")
            return
        
        print("  → Creando tabla temporal...")
        conn.execute(text("""
            CREATE TABLE community_invitation_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                community_id INTEGER NOT NULL,
                inviter_id INTEGER NOT NULL,
                invitee_email VARCHAR(120),
                invitee_phone VARCHAR(30),
                invitee_name VARCHAR(200),
                token VARCHAR(128) NOT NULL UNIQUE,
                message TEXT,
                invitation_method VARCHAR(20) DEFAULT 'email',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                accepted_at DATETIME,
                is_used BOOLEAN DEFAULT 0,
                accepted_by_user_id INTEGER,
                FOREIGN KEY (community_id) REFERENCES coach_community(id),
                FOREIGN KEY (inviter_id) REFERENCES user(id),
                FOREIGN KEY (accepted_by_user_id) REFERENCES user(id)
            )
        """))
        conn.commit()
        
        print("  → Copiando datos existentes...")
        conn.execute(text("""
            INSERT INTO community_invitation_new 
                (id, community_id, inviter_id, invitee_email, invitee_name, 
                 token, message, invitation_method, created_at, expires_at, 
                 accepted_at, is_used, accepted_by_user_id)
            SELECT 
                id, community_id, inviter_id, invitee_email, invitee_name,
                token, message, 'email', created_at, expires_at,
                accepted_at, is_used, accepted_by_user_id
            FROM community_invitation
        """))
        conn.commit()
        
        print("  → Eliminando tabla antigua...")
        conn.execute(text("DROP TABLE community_invitation"))
        conn.commit()
        
        print("  → Renombrando tabla nueva...")
        conn.execute(text("ALTER TABLE community_invitation_new RENAME TO community_invitation"))
        conn.commit()
        
        print("  → Recreando índices...")
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_community_id 
            ON community_invitation(community_id)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_inviter_id 
            ON community_invitation(inviter_id)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_invitee_email 
            ON community_invitation(invitee_email)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_invitee_phone 
            ON community_invitation(invitee_phone)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_token 
            ON community_invitation(token)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_created_at 
            ON community_invitation(created_at)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_expires_at 
            ON community_invitation(expires_at)
        """))
        conn.execute(text("""
            CREATE INDEX idx_community_invitation_is_used 
            ON community_invitation(is_used)
        """))
        conn.execute(text("""
            CREATE INDEX idx_invitation_email_community 
            ON community_invitation(invitee_email, community_id)
        """))
        conn.commit()
        
        print("  ✓ Tabla recreada con nuevos campos")


def migrate_postgresql(engine):
    """Migración para PostgreSQL"""
    print("\n🐘 Iniciando migración PostgreSQL...")
    
    with engine.connect() as conn:
        print("  → Verificando tabla community_invitation...")
        
        # Verificar si los campos ya existen
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'community_invitation'
        """))
        columns = [row[0] for row in result]
        
        needs_migration = False
        
        if 'invitee_phone' not in columns:
            print("  → Agregando campo invitee_phone...")
            conn.execute(text("""
                ALTER TABLE community_invitation 
                ADD COLUMN invitee_phone VARCHAR(30)
            """))
            conn.execute(text("""
                CREATE INDEX idx_community_invitation_invitee_phone 
                ON community_invitation(invitee_phone)
            """))
            needs_migration = True
        
        if 'invitation_method' not in columns:
            print("  → Agregando campo invitation_method...")
            conn.execute(text("""
                ALTER TABLE community_invitation 
                ADD COLUMN invitation_method VARCHAR(20) DEFAULT 'email'
            """))
            needs_migration = True
        
        # Hacer invitee_email nullable
        print("  → Haciendo invitee_email nullable...")
        conn.execute(text("""
            ALTER TABLE community_invitation 
            ALTER COLUMN invitee_email DROP NOT NULL
        """))
        
        # Actualizar registros existentes
        print("  → Actualizando registros existentes...")
        conn.execute(text("""
            UPDATE community_invitation 
            SET invitation_method = 'email' 
            WHERE invitation_method IS NULL
        """))
        
        conn.commit()
        
        if needs_migration:
            print("  ✓ Campos agregados exitosamente")
        else:
            print("  ✓ Los campos ya existían")


def main():
    """Ejecuta la migración"""
    print("=" * 70)
    print("MIGRACIÓN: Agregar métodos de invitación (Email, WhatsApp, SMS)")
    print("=" * 70)
    
    try:
        # Detectar base de datos
        database_url, db_type = get_database_url()
        
        # Crear conexión
        print(f"\n🔌 Conectando a base de datos ({db_type})...")
        engine = create_engine(database_url)
        
        # Ejecutar migración según tipo de BD
        if db_type == 'sqlite':
            migrate_sqlite(engine)
        else:
            migrate_postgresql(engine)
        
        print("\n" + "=" * 70)
        print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
        print("=" * 70)
        print("\n📝 Cambios realizados:")
        print("  • Campo invitee_phone agregado (VARCHAR(30), nullable)")
        print("  • Campo invitation_method agregado (VARCHAR(20), default 'email')")
        print("  • Campo invitee_email ahora es nullable")
        print("  • Índices creados para optimizar búsquedas")
        print("\n💡 Ahora puedes enviar invitaciones por:")
        print("  📧 Email")
        print("  📱 WhatsApp")
        print("  📲 SMS")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ ERROR durante la migración: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
