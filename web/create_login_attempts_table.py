#!/usr/bin/env python
"""Script para crear la tabla `login_attempts` en la base de datos."""

import sys
from pathlib import Path

# Agregar el directorio del proyecto al path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import app, db

def main():
    """Crea la tabla `login_attempts` (vía db.create_all())."""
    with app.app_context():
        try:
            # Crear tablas
            db.create_all()
            print("✅ Tabla 'login_attempts' creada exitosamente!")
            
            # Verificar que exista
            inspector = db.inspect(db.engine)
            if 'login_attempts' in inspector.get_table_names():
                columns = [c['name'] for c in inspector.get_columns('login_attempts')]
                print(f"📊 Columnas: {', '.join(columns)}")
            else:
                print("❌ Error: La tabla no se creó correctamente")
                return 1
                
        except Exception as e:
            print(f"❌ Error al crear la tabla: {e}")
            return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
