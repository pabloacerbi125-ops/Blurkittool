from models import db
from flask import Flask
import os

app = Flask(__name__)

# Configuración igual que en app.py
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'blurkit.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()
    print('¡Tablas creadas correctamente en', db_path, '!')
