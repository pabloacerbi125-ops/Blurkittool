"""Migration script to convert mods.json to SQLite database.

Run this script once to migrate your existing data.
"""

import sys
import os
import json
from pathlib import Path
from getpass import getpass

# Add web directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask
from flask_bcrypt import Bcrypt
from models import db, User, Mod
from core import load_mods

# Create minimal Flask app for migration
app = Flask(__name__)

# Database path - use absolute path
basedir = Path(__file__).resolve().parent
db_path = basedir / 'instance' / 'blurkit.db'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'migration-temp-key'

db.init_app(app)
bcrypt = Bcrypt(app)


def create_admin_user():
    """Create the first admin user."""
    print("\n" + "="*60)
    print("CREAR USUARIO ADMINISTRADOR")
    print("="*60)
    
    username = input("Nombre de usuario: ").strip()
    if not username:
        print("❌ El nombre de usuario es requerido.")
        sys.exit(1)
    
    email = input("Email: ").strip()
    if not email:
        print("❌ El email es requerido.")
        sys.exit(1)
    
    password = getpass("Contraseña: ")
    password_confirm = getpass("Confirmar contraseña: ")
    
    if password != password_confirm:
        print("❌ Las contraseñas no coinciden.")
        sys.exit(1)
    
    if len(password) < 6:
        print("❌ La contraseña debe tener al menos 6 caracteres.")
        sys.exit(1)
    
    # Create admin user
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role='admin',
        is_active=True
    )
    
    db.session.add(admin)
    db.session.commit()
    
    print(f"\n✅ Usuario administrador '{username}' creado exitosamente!")
    return admin


def migrate_mods_from_json():
    """Migrate mods from mods.json to database."""
    print("\n" + "="*60)
    print("MIGRAR MODS DESDE mods.json")
    print("="*60)
    
    try:
        mods_data = load_mods()
        print(f"📄 Se encontraron {len(mods_data)} mods en mods.json")
    except Exception as e:
        print(f"⚠️  No se pudo leer mods.json: {e}")
        print("⚠️  Se continuará sin migrar mods.")
        return 0
    
    migrated = 0
    skipped = 0
    
    for mod_data in mods_data:
        name = mod_data.get('name')
        if not name:
            skipped += 1
            continue
        
        # Check if mod already exists
        existing = Mod.query.filter_by(name=name).first()
        if existing:
            print(f"⏭️  Mod '{name}' ya existe, omitiendo...")
            skipped += 1
            continue
        
        # Create new mod
        mod = Mod(
            name=name,
            status=mod_data.get('status', 'prohibido'),
            category=mod_data.get('category', ''),
            platform=mod_data.get('platform', ''),
            description=mod_data.get('description', mod_data.get('notes', '')),
        )
        
        # Handle aliases (could be 'alias' or 'aliases')
        aliases = mod_data.get('alias', mod_data.get('aliases', []))
        mod.set_aliases_list(aliases)
        
        db.session.add(mod)
        migrated += 1
        print(f"✅ Migrado: {name}")
    
    db.session.commit()
    
    print(f"\n📊 Migración completada:")
    print(f"   ✅ {migrated} mods migrados")
    print(f"   ⏭️  {skipped} mods omitidos (ya existían o sin nombre)")
    
    return migrated


def main():
    """Main migration function."""
    print("\n" + "="*60)
    print("MIGRACIÓN DE DATOS - BlurkitModsTool")
    print("="*60)
    print("\nEste script migrará tus datos a SQLite y creará un usuario admin.\n")
    
    with app.app_context():
        # Create instance directory if it doesn't exist
        instance_path = Path(app.root_path) / 'instance'
        instance_path.mkdir(exist_ok=True)
        
        # Create all tables
        print("📦 Creando tablas de base de datos...")
        db.create_all()
        print("✅ Tablas creadas exitosamente!\n")
        
        # Check if admin already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            print(f"ℹ️  Ya existe un usuario administrador: {existing_admin.username}")
            create_new = input("\n¿Deseas crear otro usuario administrador? (s/n): ").lower()
            if create_new == 's':
                create_admin_user()
        else:
            create_admin_user()
        
        # Migrate mods
        migrate_mods_from_json()
        
        # Summary
        total_users = User.query.count()
        total_mods = Mod.query.count()

        print("\n" + "="*60)
        print("RESUMEN FINAL")
        print("="*60)
        print(f"👥 Total usuarios: {total_users}")
        print(f"📦 Total mods: {total_mods}")
        print(f"📁 Base de datos: {app.config['SQLALCHEMY_DATABASE_URI']}")
        print("\n✅ ¡Migración completada exitosamente!")
        print("\n💡 Ahora puedes ejecutar la aplicación con:")
        print("   python app.py")
        print("="*60 + "\n")

        # Automatizar commit y push de la base de datos si hubo cambios
        import subprocess
        db_file = str(db_path)
        try:
            subprocess.run(['git', 'add', db_file], check=True)
            subprocess.run(['git', 'commit', '-m', 'chore: sync blurkit.db after migration'], check=True)
            subprocess.run(['git', 'push'], check=True)
            print('✔️  Base de datos sincronizada con GitHub.')
        except Exception as e:
            print(f'⚠️  No se pudo sincronizar la base de datos automáticamente: {e}')


if __name__ == '__main__':
    main()
