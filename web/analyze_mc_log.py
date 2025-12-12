import sys
import re
import spacy
import json

# Cargar modelo spaCy inglés
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

def extract_player(log_lines):
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

def extract_mc_version(log_lines):
    for line in log_lines:
        if "Minecraft" in line and "version" in line.lower():
            match = re.search(r"Minecraft.*version[\s:]*([\w.\-]+)", line, re.IGNORECASE)
            if match:
                return match.group(1)
    return None

def extract_mods(log_lines):
    mods = set()
    # Buscar mods en líneas típicas
    for line in log_lines:
        # Forge/Fabric mods
        mod_match = re.findall(r"added by mods \[([^\]]+)\]", line)
        for group in mod_match:
            for mod in group.split(","):
                mods.add(mod.strip())
        # Entrypoint mods
        entry_match = re.search(r"Found Entrypoint\(.*?\) ([\w.]+)", line)
        if entry_match:
            mod = entry_match.group(1).split(".")[0]
            mods.add(mod)
        # Mods con nombre explícito
        for mod in ["Lithium", "Sodium", "Iris", "Krypton", "Indium", "ModMenu", "MoreCulling", "SodiumExtra", "FabricSkyBoxes"]:
            if mod.lower() in line.lower():
                mods.add(mod)
    return sorted(list(mods))

def extract_other_data(log_lines):
    # Puedes agregar más extractores aquí
    return {}

def main():
    if len(sys.argv) < 2:
        print("Uso: python analyze_mc_log.py <ruta_log>")
        sys.exit(1)
    log_path = sys.argv[1]
    with open(log_path, encoding="utf-8", errors="ignore") as f:
        log_lines = f.readlines()
    player = extract_player(log_lines)
    mc_version = extract_mc_version(log_lines)
    mods = extract_mods(log_lines)
    other = extract_other_data(log_lines)
    result = {
        "player": player,
        "mc_version": mc_version,
        "mods": mods,
        **other
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
