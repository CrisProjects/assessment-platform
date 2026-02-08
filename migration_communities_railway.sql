-- ============================================================================
-- MIGRACIÓN: Sistema de Comunidades de Coaches para Railway/PostgreSQL
-- Fecha: 8 de Febrero 2026
-- Descripción: Crea tablas coach_community, community_membership, community_invitation
-- ============================================================================

-- 1. CREAR TABLA coach_community
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
);

-- Índices para coach_community
CREATE INDEX IF NOT EXISTS ix_coach_community_creator_id ON coach_community(creator_id);
CREATE INDEX IF NOT EXISTS ix_coach_community_is_active ON coach_community(is_active);
CREATE INDEX IF NOT EXISTS ix_coach_community_created_at ON coach_community(created_at);
CREATE INDEX IF NOT EXISTS ix_coach_community_privacy ON coach_community(privacy);

-- 2. CREAR TABLA community_membership
CREATE TABLE IF NOT EXISTS community_membership (
    id SERIAL PRIMARY KEY,
    community_id INTEGER NOT NULL REFERENCES coach_community(id) ON DELETE CASCADE,
    coach_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(community_id, coach_id)
);

-- Índices para community_membership
CREATE INDEX IF NOT EXISTS ix_community_membership_community_id ON community_membership(community_id);
CREATE INDEX IF NOT EXISTS ix_community_membership_coach_id ON community_membership(coach_id);
CREATE INDEX IF NOT EXISTS ix_community_membership_is_active ON community_membership(is_active);
CREATE INDEX IF NOT EXISTS idx_community_active ON community_membership(community_id, is_active);

-- 3. CREAR TABLA community_invitation
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
);

-- Índices para community_invitation
CREATE INDEX IF NOT EXISTS ix_community_invitation_token ON community_invitation(token);
CREATE INDEX IF NOT EXISTS ix_community_invitation_community_id ON community_invitation(community_id);
CREATE INDEX IF NOT EXISTS ix_community_invitation_invitee_email ON community_invitation(invitee_email);
CREATE INDEX IF NOT EXISTS ix_community_invitation_is_used ON community_invitation(is_used);

-- ============================================================================
-- VERIFICACIÓN DE TABLAS CREADAS
-- ============================================================================
-- Para verificar que las tablas se crearon correctamente, ejecuta:
-- SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%community%';

-- ============================================================================
-- ✅ MIGRACIÓN COMPLETADA
-- ============================================================================
-- Ahora la página coach-comunidad puede crear y editar comunidades.
-- Las APIs en /api/communities están listas para usarse.
-- ============================================================================
