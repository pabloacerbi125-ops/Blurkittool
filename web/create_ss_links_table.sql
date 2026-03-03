-- =====================================================================
-- Crear tabla ss_links en PostgreSQL
-- =====================================================================
-- Enlaces/descargas para la vista /HerramientaSS
-- =====================================================================

CREATE TABLE IF NOT EXISTS ss_links (
  id SERIAL PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  url VARCHAR(500) NOT NULL,
  icon VARCHAR(50),
  description VARCHAR(300),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_ss_links_created_at ON ss_links(created_at);

-- Confirmar
SELECT 'Tabla ss_links creada correctamente' AS status;
