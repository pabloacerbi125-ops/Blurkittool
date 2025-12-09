"""Quick migration script with default admin credentials."""

import sys
from pathlib import Path

# Add web directory to path
web_dir = Path(__file__).parent
sys.path.insert(0, str(web_dir))

from migrate_json_to_db import main
from models import db
from app import app

if __name__ == '__main__':
    with app.app_context():
        # Create tables
        db.create_all()
        print("✓ Tablas creadas")
        
        # Now run the migration
        print("\nEjecutando migración...")
        main()
