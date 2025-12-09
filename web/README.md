Prototipo web para BlurkitModsTool

Requisitos:
- Python 3.9+

Instalación (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r web\requirements.txt
python web\app.py
```

Abrir en el navegador: `http://127.0.0.1:5000`

Empaquetar en un solo EXE con PyInstaller (Windows):

1) Instalar PyInstaller en el entorno:

```powershell
pip install pyinstaller
```

2) Ejecutar PyInstaller (ajusta nombres si deseas):

```powershell
pyinstaller --onefile --add-data "web\\templates;web\\templates" --add-data "mods.json;." web\\app.py -n BlurkitToolWeb
```

Notas:
- La opción `--add-data` copia los templates y el `mods.json` al ejecutable. En algunos casos puede ser necesario añadir la carpeta `web` completa.
- El EXE generado abrirá un servidor local. Al ejecutarlo, abre el navegador manualmente en `http://127.0.0.1:5000`.
- Para una experiencia más "nativa" se puede integrar `pywebview` y empaquetar, pero es un paso adicional.
