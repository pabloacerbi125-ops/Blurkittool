import sys
import re
import spacy
import json
from typing import List, Dict, Any

# Cargar modelo spaCy inglés
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

def extract_player(log_lines: List[str]) -> str:
    for line in log_lines:
        if "Setting user:" in line:
            match = re.search(r"Setting user: ([^\s]+)", line)
            if match:
                return match.group(1)
        if "Loaded content for [" in line:
            match = re.search(r"Loaded content for \[([^\]]+)\]", line)
            if match:
                return match.group(1)
    return None

def extract_mc_version(log_lines: List[str]) -> str:
    # 1. Buscar líneas que contengan 'minecraft' y una versión
    for line in log_lines:
        match = re.search(r"minecraft[\s:=-]*v?(1\.[0-9]+(\.[0-9]+)?)", line, re.IGNORECASE)
        if match:
            return match.group(1)
    # 2. Buscar líneas con 'version' y un patrón de versión
    for line in log_lines:
        match = re.search(r"version[\s:=-]*v?(1\.[0-9]+(\.[0-9]+)?)", line, re.IGNORECASE)
        if match:
            return match.group(1)
    # 3. Buscar cualquier patrón 1.x.x en líneas que mencionen fabricloader, loader, etc.
    for line in log_lines:
        if any(word in line.lower() for word in ["fabricloader", "loader", "forge", "fabric"]):
            match = re.search(r"(1\.[0-9]+(\.[0-9]+)?)", line)
            if match:
                return match.group(1)
    # 4. Fallback: cualquier 1.x.x en el log
    for line in log_lines:
        match = re.search(r"(1\.[0-9]+(\.[0-9]+)?)", line)
        if match:
            return match.group(1)
    return None

def extract_mods(log_lines: List[str]) -> List[Dict[str, Any]]:
    mods = set()
    mod_details = {}
    for line in log_lines:
        # Forge/Fabric mods
        mod_match = re.findall(r"added by mods \[([^\]]+)\]", line)
        for group in mod_match:
            for mod in group.split(","):
                mods.add(mod.strip())
        # Entrypoint mods
        entry_match = re.search(r"Found Entrypoint\\(.*?\\) ([\\w.]+)", line)
        if entry_match:
            mod = entry_match.group(1).split(".")[0]
            mods.add(mod)
        # Mods con nombre explícito
        for mod in ["Lithium", "Sodium", "Iris", "Krypton", "Indium", "ModMenu", "MoreCulling", "SodiumExtra", "FabricSkyBoxes"]:
            if mod.lower() in line.lower():
                mods.add(mod)
        # Buscar versiones de mods
        mod_ver = re.search(r"Loaded configuration file for ([\w]+):.*", line)
        if mod_ver:
            mod_name = mod_ver.group(1)
            mod_details[mod_name] = {}
        # Ejemplo: [main/INFO]: Loaded configuration file for Lithium: 144 options available, 1 override(s) found
    # Convertir a lista de dicts
    mod_list = []
    for mod in mods:
        mod_list.append({"name": mod, **mod_details.get(mod, {})})
    return sorted(mod_list, key=lambda x: x["name"])

def extract_client(log_lines: List[str]) -> str:
    for line in log_lines:
        if "Lunar client" in line or "LunarClient" in line:
            return "LunarClient"
        if "Forge" in line:
            return "Forge"
        if "Fabric" in line:
            return "Fabric"
    return None

def extract_errors(log_lines: List[str]) -> List[str]:
    errors = []
    for line in log_lines:
        if "error" in line.lower() or "exception" in line.lower():
            errors.append(line.strip())
    return errors

def analyze_log_lines(log_lines: List[str]) -> Dict[str, Any]:
    player = extract_player(log_lines)
    mc_version = extract_mc_version(log_lines)
    player_with_version = None
    if player and mc_version:
        player_with_version = f"{player} (MC {mc_version})"
    elif player:
        player_with_version = player
    elif mc_version:
        player_with_version = f"MC {mc_version}"
    return {
        "player": player,
        "mc_version": mc_version,
        "player_with_version": player_with_version,
        "mods": extract_mods(log_lines),
        "client": extract_client(log_lines),
        "errors": extract_errors(log_lines)
    }

def main():
    if len(sys.argv) < 2:
        print("Uso: python analyze_mc_log.py <ruta_log>")
        sys.exit(1)
    log_path = sys.argv[1]
    with open(log_path, encoding="utf-8", errors="ignore") as f:
        log_lines = f.readlines()
    result = analyze_log_lines(log_lines)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
