"""Launcher script for BlurkitTool - Opens Flask app in browser"""
import webbrowser
import time
import sys
import os
from pathlib import Path
from threading import Thread

# Configurar rutas para PyInstaller
if getattr(sys, 'frozen', False):
    # Running in PyInstaller bundle
    bundle_dir = sys._MEIPASS
    os.chdir(bundle_dir)
else:
    # Running in normal Python
    bundle_dir = Path(__file__).parent

# Add paths
sys.path.insert(0, str(bundle_dir))
sys.path.insert(0, str(Path(bundle_dir) / 'web'))

# Importar Flask primero
import flask
from flask import Flask, render_template, request, redirect, url_for

# Ahora importar la aplicación
import web.app as webapp
app = webapp.app

def open_browser():
    """Open browser after 1.5 seconds"""
    time.sleep(1.5)
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    # Detectar si se pasó --no-browser como argumento (desde Electron)
    no_browser = '--no-browser' in sys.argv
    
    if not no_browser:
        # Start browser in background
        Thread(target=open_browser, daemon=True).start()
        print("Abriendo en el navegador...")
    else:
        print("Ejecutando desde Electron (sin abrir navegador)...")
    
    # Run Flask (without debug mode for production)
    print("Iniciando BlurkitTool...")
    app.run(port=5000, debug=False)
