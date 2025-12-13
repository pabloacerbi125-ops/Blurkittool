"""Script to migrate user roles from old names to new names.

Old roles -> New roles:
- viewer -> helper
- editor -> smod
"""

import sys
from pathlib import Path

# Make sure web module can import models
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import app, db
from models import User

def migrate_roles():
    """Update user roles from old to new naming system."""
    
    with app.app_context():
        # Map old roles to new roles
        role_mapping = {
            'viewer': 'helper',
            'editor': 'smod',
            'admin': 'admin'  # admin stays the same
        }
        
        print("Starting role migration...")
        print("-" * 50)
        
        users = User.query.all()
        updated_count = 0
        
        for user in users:
            old_role = user.role
            
            if old_role in role_mapping:
                new_role = role_mapping[old_role]
                
                if old_role != new_role:  # Only update if role actually changes
                    user.role = new_role
                    updated_count += 1
                    print(f"Updated: {user.username} ({old_role} -> {new_role})")
                else:
                    print(f"Unchanged: {user.username} ({old_role})")
            else:
                print(f"Warning: Unknown role '{old_role}' for user {user.username}")
        
        if updated_count > 0:
            db.session.commit()
            print("-" * 50)
            print(f"✅ Migration completed! Updated {updated_count} user(s).")
            # Automatizar commit y push de la base de datos si hay cambios
            import subprocess
            import os
            db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance', 'blurkit.db'))
            try:
                subprocess.run(['git', 'add', db_file], check=True)
                subprocess.run(['git', 'commit', '-m', 'chore: sync blurkit.db after role/user change'], check=True)
                subprocess.run(['git', 'push'], check=True)
                print('✔️  Base de datos sincronizada con GitHub.')
            except Exception as e:
                print(f'⚠️  No se pudo sincronizar la base de datos automáticamente: {e}')
        else:
            print("-" * 50)
            print("No updates needed. All users already have new role names.")
        
        # Show final state
        print("\n📊 Current users and roles:")
        print("-" * 50)
        for user in User.query.all():
            print(f"  {user.username}: {user.role}")

if __name__ == '__main__':
    migrate_roles()
