"""Flask web application for BlurkitModsTool.

Provides simple routes to list, add, edit and analyze mods using the
`web/core.py` utilities. Designed to be run locally and optionally
packaged with PyInstaller.
"""

import sys
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for

# helper to locate resources when packaged with PyInstaller
def resource_path(relative_path):
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).resolve().parent
    return base / relative_path

# make sure web module can import core
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import load_mods, save_mods, analizar_log_desde_lineas

# Flask app with proper paths
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True


@app.route('/')
def menu():
    try:
        return render_template('menu.html')
    except Exception as e:
        import traceback
        return f"<pre>Error: {str(e)}\n\n{traceback.format_exc()}</pre>", 500


@app.route('/mods')
def index():
    mods = load_mods()
    # Crear listas con tuplas (índice_real, mod)
    prohibidos = [(i, m) for i, m in enumerate(mods) if m.get('status') == 'prohibido']
    permitidos = [(i, m) for i, m in enumerate(mods) if m.get('status') == 'permitido']
    return render_template('index.html', prohibidos=prohibidos, permitidos=permitidos)


@app.route('/add_mod', methods=['POST'])
def add_mod():
    mods = load_mods()
    nuevo_nombre = request.form.get('name', '').strip()
    
    # Validar que no exista duplicado
    for m in mods:
        if m.get('name', '').lower() == nuevo_nombre.lower():
            return render_template('index.html', 
                prohibidos=[(i, m) for i, m in enumerate(mods) if m.get('status') == 'prohibido'],
                permitidos=[(i, m) for i, m in enumerate(mods) if m.get('status') == 'permitido'],
                error=f'Ya existe un mod con el nombre "{nuevo_nombre}"')
    
    nuevo = {
        'name': nuevo_nombre,
        'status': request.form.get('status', 'prohibido'),
        'category': request.form.get('category', '').strip(),
        'platform': request.form.get('platform', '').strip(),
        'description': request.form.get('description', '').strip(),
        'alias': [x.strip() for x in request.form.get('alias', '').replace('-', ',').split(',') if x.strip()]
    }
    mods.append(nuevo)
    save_mods(mods)
    return redirect(url_for('index'))


@app.route('/edit/<int:idx>', methods=['GET', 'POST'])
def edit(idx):
    mods = load_mods()
    if idx < 0 or idx >= len(mods):
        return redirect(url_for('index'))
    if request.method == 'POST':
        nuevo_nombre = request.form.get('name', '').strip()
        
        # Validar que no exista duplicado (excepto el mismo mod)
        for i, m in enumerate(mods):
            if i != idx and m.get('name', '').lower() == nuevo_nombre.lower():
                return render_template('edit.html', idx=idx, mod=mods[idx],
                    error=f'Ya existe otro mod con el nombre "{nuevo_nombre}"')
        
        mods[idx] = {
            'name': nuevo_nombre,
            'status': request.form.get('status', 'prohibido'),
            'category': request.form.get('category', '').strip(),
            'platform': request.form.get('platform', '').strip(),
            'description': request.form.get('description', '').strip(),
            'alias': [x.strip() for x in request.form.get('alias', '').replace('-', ',').split(',') if x.strip()]
        }
        save_mods(mods)
        return redirect(url_for('index'))
    mod = mods[idx]
    return render_template('edit.html', idx=idx, mod=mod)


@app.route('/delete/<int:idx>', methods=['POST'])
def delete(idx):
    mods = load_mods()
    if 0 <= idx < len(mods):
        mods.pop(idx)
        save_mods(mods)
    return redirect(url_for('index'))


@app.route('/analyze', methods=['POST'])
def analyze():
    mods = load_mods()
    log_text = request.form.get('log', '')
    resultado = ''
    if log_text.strip():
        resultado = analizar_log_desde_lineas(log_text.splitlines(), mods)
    return render_template('analysis.html', resultado=resultado)


@app.route('/paste', methods=['GET'])
def paste_page():
    return render_template('paste.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template('upload.html')
    f = request.files.get('logfile')
    if not f:
        return render_template('analysis.html', resultado='No se subió archivo.')
    try:
        content = f.read().decode('utf-8', errors='ignore')
    except Exception:
        content = f.read().decode('latin-1', errors='ignore')
    mods = load_mods()
    resultado = analizar_log_desde_lineas(content.splitlines(), mods)
    return render_template('analysis.html', resultado=resultado)


@app.route('/search', methods=['GET', 'POST'])
def search():
    resultado = None
    if request.method == 'POST':
        term = request.form.get('term', '').lower().strip()
        mods = load_mods()
        encontrados = []
        for m in mods:
            # Buscar en nombre
            if term in m.get('name','').lower():
                encontrados.append(m)
                continue
            # Buscar en alias
            alias_list = m.get('alias', [])
            if any(term in alias.lower() for alias in alias_list):
                encontrados.append(m)
        resultado = encontrados
    return render_template('search.html', resultado=resultado)


if __name__ == '__main__':
    # run on localhost only; open browser manually
    app.run(port=5000, debug=True)
