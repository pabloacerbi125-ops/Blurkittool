-- =====================================================================
-- Script SQL para crear tabla comandos_staff en PostgreSQL
-- =====================================================================
-- Ejecutar con: psql -d blurkit -f create_comandos_staff_table.sql
-- =====================================================================

-- Crear tabla comandos_staff
CREATE TABLE IF NOT EXISTS comandos_staff (
  id SERIAL PRIMARY KEY,
  rango VARCHAR(64) NOT NULL,
  nombre VARCHAR(200) NOT NULL,
  descripcion TEXT,
  informacion TEXT,
  orden INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Crear índices
CREATE INDEX IF NOT EXISTS idx_comandos_staff_rango ON comandos_staff(rango);
CREATE INDEX IF NOT EXISTS idx_comandos_staff_orden ON comandos_staff(orden);

-- Insertar datos iniciales (opcional - puedes borrar si no quieres datos pre-cargados)
INSERT INTO comandos_staff (rango, nombre, descripcion, informacion, orden) VALUES
-- p-helper
('p-helper', '!ayuda', 'Muestra ayuda general', 'Comando para obtener ayuda general del servidor y de otros comandos disponibles.', 0),
('p-helper', '!info', 'Ver información del servidor', 'Obtén información detallada del servidor, jugadores conectados y estadísticas.', 1),
-- helper
('helper', '!mute', 'Silencia a un jugador', 'Silencia a un jugador especificado durante el tiempo indicado. El jugador no podrá escribir en el chat.', 0),
('helper', '!unmute', 'Dessilencia a un jugador', 'Remueve el silencio de un jugador, permitiéndole escribir en el chat nuevamente.', 1),
-- mod
('mod', '!ban', 'Banea a un jugador', 'Banea a un jugador del servidor de forma permanente o temporal. Se registra en la base de datos de bans.', 0),
('mod', '!unban', 'Desbanea a un jugador', 'Remueve el ban de un jugador, permitiéndole conectarse nuevamente al servidor.', 1),
-- smod
('smod', '!kick', 'Expulsa a un jugador', 'Expulsa a un jugador del servidor. El jugador puede volver a conectarse inmediatamente.', 0),
('smod', '!warn', 'Advierte a un jugador', 'Envía una advertencia a un jugador por incumplimiento de reglas. Después de 3 advertencias, puede resultar en ban.', 1),
-- admin
('admin', '!shutdown', 'Reinicia el servidor', 'Reinicia el servidor de forma segura, desconectando a todos los jugadores con aviso previo.', 0),
('admin', '!config', 'Edita configuración', 'Abre el panel de configuración del servidor para ajustar parámetros, dificultad, y más opciones.', 1)
ON CONFLICT DO NOTHING;

-- Confirmación
SELECT 'Tabla comandos_staff creada correctamente' AS status;
