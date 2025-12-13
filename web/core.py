# Cargar mods desde la base de datos SQLite
import sqlite3

def load_mods(db_path=None):
    """Carga los mods desde la base de datos SQLite y los devuelve como lista de dicts."""
    # Buscar la base de datos en la ruta más probable
    posibles = [
        'web/instance/blurkit.db',
        'instance/blurkit.db',
        './web/instance/blurkit.db',
        './instance/blurkit.db'
    ]
    if db_path is not None:
        posibles.insert(0, db_path)
    for path in posibles:
        if os.path.exists(path):
            db_path = path
            break
    else:
        raise FileNotFoundError("No se encontró la base de datos SQLite de mods.")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name, status, category, platform FROM mods")
    mods = []
    for row in cursor.fetchall():
        mods.append({
            'name': row[0],
            'status': row[1],
            'category': row[2],
            'platform': row[3],
            'alias': []  # Si tienes alias en la tabla, agrégalo aquí
        })
    conn.close()
    return mods
"""Core utilities for Blurkit web UI.

Contains functions to load/save `mods.json` and to extract / classify mods
from Minecraft logs. Kept intentionally small and dependency-free.
"""

import json
import os
import re
import sys
from pathlib import Path

# PyInstaller detection for bundled mods.json
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
    BUNDLED_MODS = Path(sys._MEIPASS) / "mods.json"
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
    BUNDLED_MODS = None

DATA_FILE = BASE_DIR / "mods.json"
FIRST_RUN_FLAG = BASE_DIR / "first_run.flag"

DEFAULT_MODS = [
    {
        "name": "Optifine",
        "status": "permitido",
        "category": "rendimiento",
        "platform": "Java",
        "description": "Mejora graficos y rendimiento."
    }
]


# Integración del sistema inteligente de detección de mods/hacks ilegales en logs de Minecraft.
import pickle

from ml_integration import MLLogModel, load_ml_model
from log_analyzer import MinecraftLogAnalyzer

# Utilidad para normalizar nombres de mods (minúsculas y solo alfanumérico)
def normalizar(texto: str) -> str:
    """Devuelve una versión simplificada en minúsculas y solo alfanumérico para comparaciones."""
    texto = (texto or "").lower()
    return re.sub(r"[^a-z0-9]", "", texto)

def detectar_mods_ilegales_en_log(log_path, prohibited_mods_path='web/prohibited_mods.txt', model_path='web/hack_detector_model.pkl'):
    """Analiza un log y retorna una lista de detecciones de mods/hacks ilegales."""
    # Usar rutas absolutas para evitar errores
    prohibited_mods_path = str(BASE_DIR / 'web' / 'prohibited_mods.txt')
    # model_path = str(BASE_DIR / 'web' / 'hack_detector_model.pkl')
    # Cargar lista de mods prohibidos
    try:
        with open(prohibited_mods_path, 'r', encoding='utf-8') as f:
            hacks = [line.strip() for line in f if line.strip()]
    except Exception:
        hacks = []
    # ML activado solo si el modelo existe
    try:
        clf, vectorizer = load_ml_model(model_path)
        ml_model = MLLogModel(clf, vectorizer)
    except Exception:
        ml_model = None
    analyzer = MinecraftLogAnalyzer(hacks, regex_patterns=[], ml_model=ml_model)
    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    return analyzer.parse_log(lines)

# Encapsular el bloque anterior como función
def extraer_mods_cargados(lines):
    """Extrae una lista de mods detectados desde las líneas de un log."""
    vistos = set()
    orden = []
    def add(mod_id, display=None):
        mod_id = (mod_id or "").strip()
        if not mod_id or mod_id in vistos:
            return
        vistos.add(mod_id)
        orden.append({"id": mod_id, "display": display or mod_id})

    # A) Bloque "Loading X mods:"
    start = None
    for i, l in enumerate(lines):
        if "Loading" in l and "mods:" in l and "Loading Minecraft" not in l:
            start = i
            break
    if start is not None:
        for l in lines[start + 1:]:
            s = l.lstrip()
            if s.startswith("["):
                break
            if s.startswith("-"):
                content = s[1:].strip()
                if not content:
                    continue
                tokens = content.split()
                mod_id = tokens[0]
                version = " ".join(tokens[1:]) if len(tokens) > 1 else ""
                display = f"{mod_id} {version}".strip()
                add(mod_id, display)

    # B) "Loaded configuration file for X:"
    for l in lines:
        m = re.search(r"Loaded configuration file for (.+?):", l)
        if m:
            add(m.group(1))

    # C) Entrypoint Fabric
    for l in lines:
        if "Found Entrypoint(" not in l:
            continue
        m = re.search(r"Found Entrypoint\([^)]*\)\s+([A-Za-z0-9_.$:]+)", l)
        if not m:
            continue
        full_cls = m.group(1)
        full_cls = re.split(r"[:(]", full_cls)[0]
        simple = full_cls.split(".")[-1]
        simple_limpio = re.sub(r"(ClientMod|Client|Mod|Initializer|Init)$", "", simple, flags=re.IGNORECASE)
        add(simple_limpio or simple)

    # D) Forge variantes
    for i, l in enumerate(lines):
        if "Mod List:" not in l:
            continue
        for seg in lines[i + 1:]:
            if seg.startswith("["):
                break
            m = re.search(r"^\s*[-\t]*([A-Za-z0-9_.-]+)(?:\s+([^\s]+))?", seg)
            if not m:
                if not seg.startswith((" ", "\t", "-")):
                    break
                continue
            mod_id = m.group(1)
            version = m.group(2) or ""
            display = f"{mod_id} {version}".strip()
            add(mod_id, display)

    for l in lines:
        m = re.search(r"Found mod (\S+) version ([^\s]+)", l)
        if m:
            add(m.group(1), f"{m.group(1)} {m.group(2)}")

    for l in lines:
        m = re.search(r"contains mod (\S+)", l)
        if m:
            add(m.group(1))

    for l in lines:
        m = re.search(r"Registering new mod:\s+(\S+)\s+([^\s]+)", l)
        if m:
            add(m.group(1), f"{m.group(1)} {m.group(2)}")

    # E) Detectar referencias a archivos .jar en el log (ej: mods/SomeMod-1.2.3.jar)
    # Extrae el nombre del fichero, quita la extension y sufijos de version simples
    jar_re = re.compile(r"([A-Za-z0-9_\-./\\]+\.jar)", flags=re.IGNORECASE)
    for l in lines:
        for match in jar_re.findall(l):
            fname = os.path.basename(match)
            name = re.sub(r"\.jar$", "", fname, flags=re.IGNORECASE)
            # Quitar sufijos de version como -1.2.3 o _v1.2
            name_clean = re.sub(r"[-_ ]v?\d+(?:[\.\-]\d+)*(?:[A-Za-z0-9]*)$", "", name)
            add(name_clean or name, name)

    return orden


def clasificar_mod(nombre, mods):
    nombre_norm = normalizar(nombre)
    for m in mods:
        patrones = [m.get("name")] + m.get("alias", [])
        for p in patrones:
            if not p:
                continue
            if normalizar(p) == nombre_norm:
                return m
    return None


def analizar_log_desde_lineas(lines, mods):
    utiles = []
    for line in lines:
        if "Connecting to " in line or "[System] [CHAT]" in line:
            break
        utiles.append(line)


    usuario = None
<<<<<<< HEAD
    mc_version = None
=======
    version_mc = None
>>>>>>> 595f419 (Sync all changes and new files for Render deploy)
    for l in utiles:
        # Buscar usuario en varios formatos
        m = re.search(r"Setting user[:=\s]+([A-Za-z0-9_\-]+)", l)
        if not m:
            m = re.search(r"\bUser(?:name)?[:=\s]+([A-Za-z0-9_\-]+)", l, re.IGNORECASE)
        if m:
            usuario = m.group(1)
<<<<<<< HEAD
        v = re.search(r"Minecraft.*version[\s:]*([\w.\-]+)", l, re.IGNORECASE)
        if v:
            mc_version = v.group(1)
        if usuario and mc_version:
=======
        # Buscar versión de Minecraft en varios formatos
        v = re.search(r"Minecraft[\s:=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", l, re.IGNORECASE)
        if not v:
            v = re.search(r"version[\s:=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", l, re.IGNORECASE)
        if v:
            version_mc = v.group(1)
        if usuario and version_mc:
>>>>>>> 595f419 (Sync all changes and new files for Render deploy)
            break

    mods_cargados = extraer_mods_cargados(utiles)
    mods_prohibidos = []
    mods_permitidos = []
    mods_desconocidos = []

    if not mods_cargados:
        return {
            'usuario': usuario,
<<<<<<< HEAD
            'mc_version': mc_version,
=======
            'version': version_mc,
>>>>>>> 595f419 (Sync all changes and new files for Render deploy)
            'mods_prohibidos': [],
            'mods_permitidos': [],
            'mods_desconocidos': [],
            'total': 0
        }
    
    for mc in mods_cargados:
        mod_id = mc.get("id")
        display = mc.get("display", mod_id)
        info = clasificar_mod(mod_id, mods)
        
        mod_item = {
            'name': display,
            'id': mod_id,
            'category': info.get('category', 'desconocido') if info else 'desconocido',
            'platform': info.get('platform', 'Unknown') if info else 'Unknown'
        }
        
        if not info:
            mods_desconocidos.append(mod_item)
            continue
            
        estado = info.get("status")
        if estado == "permitido":
            mods_permitidos.append(mod_item)
        elif estado == "prohibido":
            mods_prohibidos.append(mod_item)
        else:
            mods_desconocidos.append(mod_item)

    return {
        'usuario': usuario,
<<<<<<< HEAD
        'mc_version': mc_version,
=======
        'version': version_mc,
>>>>>>> 595f419 (Sync all changes and new files for Render deploy)
        'mods_prohibidos': mods_prohibidos,
        'mods_permitidos': mods_permitidos,
        'mods_desconocidos': mods_desconocidos,
        'total': len(mods_cargados)
    }
