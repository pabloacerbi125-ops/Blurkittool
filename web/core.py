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
        "description": "Mejora graficos y rendimiento.",
        "alias": ["optifine", "optifime"],
    }
]


def load_mods():
    """Load mods from `mods.json`, creating it with defaults if missing.

    Returns a list of mod dictionaries.
    """
    if not DATA_FILE.exists():
        # Si está empaquetado y existe mods.json en el bundle, copiarlo
        if BUNDLED_MODS and BUNDLED_MODS.exists():
            try:
                import shutil
                shutil.copy2(BUNDLED_MODS, DATA_FILE)
                print(f"Copiado mods.json desde el paquete a {DATA_FILE}")
            except Exception as e:
                print(f"Error copiando mods.json: {e}")
                # Si falla, crear con defaults
                with DATA_FILE.open("w", encoding="utf-8") as f:
                    json.dump(DEFAULT_MODS, f, ensure_ascii=False, indent=2)
        else:
            # Crear con defaults
            try:
                with DATA_FILE.open("w", encoding="utf-8") as f:
                    json.dump(DEFAULT_MODS, f, ensure_ascii=False, indent=2)
                try:
                    FIRST_RUN_FLAG.write_text("1", encoding="utf-8")
                except Exception:
                    pass
            except Exception:
                return DEFAULT_MODS.copy()

    try:
        with DATA_FILE.open("r", encoding="utf-8") as f:
            mods = json.load(f)
            
        # Migrar formato antiguo a nuevo (aliases->alias, notes->description)
        migrated = False
        for mod in mods:
            if "aliases" in mod and "alias" not in mod:
                mod["alias"] = mod.pop("aliases")
                migrated = True
            if "notes" in mod and "description" not in mod:
                mod["description"] = mod.pop("notes")
                migrated = True
        
        # Si hubo migración, guardar automáticamente
        if migrated:
            save_mods(mods)
            
        return mods
    except Exception:
        return DEFAULT_MODS.copy()


def save_mods(mods):
    """Persist `mods` to `mods.json` (overwrites).

    `mods` should be a serializable list/dict structure.
    """
    with DATA_FILE.open("w", encoding="utf-8") as f:
        json.dump(mods, f, ensure_ascii=False, indent=2)


# Normalizacion

def normalizar(texto: str) -> str:
    """Return a simplified lower-alphanumeric-only form for comparisons."""
    texto = (texto or "").lower()
    return re.sub(r"[^a-z0-9]", "", texto)


# Extraccion de mods desde logs

def extraer_mods_cargados(lines):
    """Extract a list of detected mods from `lines` of a log file.

    Returns a list of dicts with keys `id` and `display`.
    """
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
    mc_version = None
    for l in utiles:
        m = re.search(r"Setting user:\s*(\S+)", l)
        if m:
            usuario = m.group(1)
        v = re.search(r"Minecraft.*version[\s:]*([\w.\-]+)", l, re.IGNORECASE)
        if v:
            mc_version = v.group(1)
        if usuario and mc_version:
            break

    mods_cargados = extraer_mods_cargados(utiles)
    mods_prohibidos = []
    mods_permitidos = []
    mods_desconocidos = []

    if not mods_cargados:
        return {
            'usuario': usuario,
            'mc_version': mc_version,
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
        'mc_version': mc_version,
        'mods_prohibidos': mods_prohibidos,
        'mods_permitidos': mods_permitidos,
        'mods_desconocidos': mods_desconocidos,
        'total': len(mods_cargados)
    }
