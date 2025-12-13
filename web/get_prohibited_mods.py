# get_prohibited_mods.py
"""
Script para extraer la lista de mods prohibidos y sus alias desde la base de datos.
"""
from models import db, Mod
from flask import Flask

app = Flask(__name__)
import os
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance', 'blurkit.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'  # Ruta absoluta para evitar errores
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    mods = Mod.query.filter_by(status='prohibido').all()
    hacks = set()
    for mod in mods:
        hacks.add(mod.name.lower())
        hacks.update([alias.lower() for alias in mod.get_aliases_list()])
    with open('web/prohibited_mods.txt', 'w', encoding='utf-8') as f:
        for h in sorted(hacks):
            f.write(h + '\n')
    print(f"Se han guardado {len(hacks)} mods/alias prohibidos en web/prohibited_mods.txt")
