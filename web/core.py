import openai
import json
from pathlib import Path


def load_mods(db_path=None):
    """Carga mods desde la fuente disponible.

    Prioridad:
    1) Base de datos principal vía SQLAlchemy (Postgres/SQLite según DATABASE_URL)
    2) Archivo mods.json (legacy)
    3) Base SQLite legacy (si se provee db_path o se encuentra en rutas comunes)

    Devuelve una lista de dicts con al menos: name, status, category, platform, alias.
    """
    # 1) Preferir SQLAlchemy (lo que usa la app actualmente)
    try:
        from flask import has_app_context
        if has_app_context():
            from models import Mod

            rows = Mod.query.order_by(Mod.name.asc()).all()
            mods = []
            for m in rows:
                try:
                    aliases = m.get_aliases_list()
                except Exception:
                    aliases = []
                mods.append(
                    {
                        'name': m.name,
                        'status': m.status,
                        'category': m.category,
                        'platform': m.platform,
                        'alias': aliases,
                    }
                )
            if mods:
                return mods
    except Exception:
        # Silencioso: seguimos con fallbacks
        pass

    # 2) Fallback a mods.json (legacy)
    try:
        base_dir = Path(__file__).resolve().parent.parent
        candidates = [base_dir / 'mods.json']
        for p in candidates:
            if p.exists():
                data = json.loads(p.read_text(encoding='utf-8'))
                if isinstance(data, dict) and 'mods' in data:
                    data = data['mods']
                if isinstance(data, list):
                    return data
    except Exception:
        pass

    # 3) Legacy SQLite (evitar romper, pero no fallar duro)
    try:
        import sqlite3

        possibles = []
        if db_path is not None:
            possibles.append(str(db_path))

        web_dir = Path(__file__).resolve().parent
        possibles.extend(
            [
                str(web_dir / 'instance' / 'blurkit.db'),
                str(web_dir.parent / 'instance' / 'blurkit.db'),
                'web/instance/blurkit.db',
                'instance/blurkit.db',
                './web/instance/blurkit.db',
                './instance/blurkit.db',
            ]
        )

        for path in possibles:
            try:
                if not path:
                    continue
                if not Path(path).exists():
                    continue
                conn = sqlite3.connect(path)
                cursor = conn.cursor()
                cursor.execute("SELECT name, status, category, platform FROM mods")
                mods = []
                for row in cursor.fetchall():
                    mods.append(
                        {
                            'name': row[0],
                            'status': row[1],
                            'category': row[2],
                            'platform': row[3],
                            'alias': [],
                        }
                    )
                conn.close()
                if mods:
                    return mods
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
    except Exception:
        pass

    # Nada disponible: devolvemos vacío (el analizador igual puede funcionar)
    return []


def analyze_log_with_gpt(log_text: str, openai_api_key: str) -> dict:
    """
    Analiza un log de Minecraft usando GPT-3.5-turbo y devuelve un JSON estructurado igual a analyze_mc_log_utils.py.
    """
    client = openai.OpenAI(api_key=openai_api_key)
    # Cargar mods permitidos y prohibidos desde la BD
    mods_bd = load_mods()
    permitidos = []
    prohibidos = []
    for m in mods_bd:
        if m['status'] == 'permitido':
            permitidos.append(m['name'])
            if 'alias' in m and m['alias']:
                if isinstance(m['alias'], list):
                    permitidos.extend(m['alias'])
                elif isinstance(m['alias'], str):
                    permitidos.extend([a.strip() for a in m['alias'].split(',') if a.strip()])
        elif m['status'] == 'prohibido':
            prohibidos.append(m['name'])
            if 'alias' in m and m['alias']:
                if isinstance(m['alias'], list):
                    prohibidos.extend(m['alias'])
                elif isinstance(m['alias'], str):
                    prohibidos.extend([a.strip() for a in m['alias'].split(',') if a.strip()])
    permitidos_txt = "\n".join(sorted(set(permitidos)))
    prohibidos_txt = "\n".join(sorted(set(prohibidos)))
    # PROMPT: la IA debe clasificar
    prompt = (
        "Eres un experto en análisis de logs de Minecraft.\n"
        "Tu tarea es:\n"
        "- Extraer y listar absolutamente TODOS los mods, librerías y dependencias que aparezcan en el log, aunque no estén en ninguna lista.\n"
        "- Clasifica cada mod y dependencia en uno de estos grupos: 'mods_permitidos', 'mods_prohibidos', 'mods_desconocidos', 'dependencias'.\n"
        "- Usa las siguientes listas para comparar (case-insensitive, ignora espacios y guiones):\n"
        "  - Permitidos:\n" + permitidos_txt + "\n"
        "  - Prohibidos:\n" + prohibidos_txt + "\n"
        "- Si el nombre no está en ninguna lista, ponlo en 'mods_desconocidos'.\n"
        "- Distingue dependencias/librerías si es posible (por contexto del log).\n"
        "- Para cada mod o dependencia, incluye el nombre y, si está disponible, la versión.\n"
        "El resultado debe ser un JSON con la siguiente estructura:\n"
        "{\n  'mods_permitidos': [ { 'name': '', 'version': '' } ],\n  'mods_prohibidos': [ { 'name': '', 'version': '' } ],\n  'mods_desconocidos': [ { 'name': '', 'version': '' } ],\n  'dependencias': [ { 'name': '', 'version': '' } ]\n}\n"
        "No expliques nada, solo responde con el JSON.\n"
        "\nLOG:\n" + log_text[:8000] + "\n"
    )
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024,
        temperature=0.1,
    )
    import json as _json
    import re as _re
    content = response.choices[0].message.content
    match = _re.search(r'\{.*\}', content, _re.DOTALL)
    if match:
        try:
            return _json.loads(match.group(0))
        except Exception:
            pass
    return {"error": "No se pudo analizar el JSON", "raw": content}

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
    version_mc = None
    for l in utiles:
        # Buscar usuario en varios formatos
        m = re.search(r"Setting user[:=\s]+([A-Za-z0-9_\-]+)", l)
        if not m:
            m = re.search(r"\bUser(?:name)?[:=\s]+([A-Za-z0-9_\-]+)", l, re.IGNORECASE)
        if m:
            usuario = m.group(1)
        # Buscar versión de Minecraft en varios formatos
        v = re.search(r"Minecraft[\s:=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", l, re.IGNORECASE)
        if not v:
            v = re.search(r"version[\s:=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", l, re.IGNORECASE)
        if v:
            version_mc = v.group(1)
        if usuario and version_mc:
            break

    mods_cargados = extraer_mods_cargados(utiles)
    mods_prohibidos = []
    mods_permitidos = []
    mods_desconocidos = []

    if not mods_cargados:
        return {
            'usuario': usuario,
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
        'mods_prohibidos': mods_prohibidos,
        'mods_permitidos': mods_permitidos,
        'mods_desconocidos': mods_desconocidos,
        'total': len(mods_cargados)
    }
