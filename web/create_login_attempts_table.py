#!/usr/bin/env python
"""Script to create the login_attempts table in the database."""

import sys
from pathlib import Path

# Add web directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import app, db
from models import LoginAttempt

def main():
    """Create the login_attempts table."""
    with app.app_context():
        try:
            # Create the table
            db.create_all()
            print("✅ Tabla 'login_attempts' creada exitosamente!")
            
            # Verify the table exists
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
