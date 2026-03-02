-- =====================================================================
-- Crear tabla ss_sessions en PostgreSQL
-- =====================================================================
-- Sessions temporales para "Herramientas SS" (autenticación con 2FA)
-- Válidas por 10 minutos exactos desde su creación
-- =====================================================================

CREATE TABLE IF NOT EXISTS ss_sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Crear índices
CREATE INDEX IF NOT EXISTS idx_ss_sessions_user_id ON ss_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_ss_sessions_token ON ss_sessions(token);
CREATE INDEX IF NOT EXISTS idx_ss_sessions_expires_at ON ss_sessions(expires_at);

-- Confirmar
SELECT 'Tabla ss_sessions creada correctamente' AS status;
