import sys
import re
import json
from typing import List, Dict, Any



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
    dependencies = set()
    dependency_patterns = [
        r"^fabric(-|$)", r"^fabricloader$", r"^fabric-api", r"^mixinextras$", r"^org_", r"^io_", r"^net_", r"^com_", r"^org\\.", r"^io\\.", r"^net\\.", r"^com\\.", r"^antlr", r"^jcpp$", r"^glsl", r"^resource-loader", r"^lwjgl", r"^block-view", r"^key-binding", r"^command-api", r"^lifecycle-events", r"^rendering-", r"^events-", r"^base$", r"^v[0-9]+$", r"^common$", r"^indigo$", r"^attachment$", r"^exampleinits$", r"^customingredientsync$", r"^customingredientinit$", r"^legacyhandler$", r"^lootinitializer$", r"^resourceconditionsimpl$", r"^packagemanager$", r"^modinitializer$", r"^pipeline$", r"^renderingcallbackinvoker$"
    ]
    def is_dependency(mod_name):
        for pat in dependency_patterns:
            if re.search(pat, mod_name, re.IGNORECASE):
                return True
        return False
    # 1. Detectar bloque "Loading X mods:" (Fabric/Forge)
    loading_mods = False
    for line in log_lines:
        if re.search(r"Loading \d+ mods", line):
            loading_mods = True
            continue
        if loading_mods:
            # Fin del bloque si la línea empieza con [ o está vacía
            if line.strip().startswith("[") or not line.strip():
                loading_mods = False
                continue
            # Detectar mods y dependencias anidadas
            # Ejemplo: "- sodium 0.4.10", "|-- fabric-api-base 0.4.31+1802ada577", "\-- mixinextras 0.5.0"
            m = re.match(r"[|\\\-]*\s*([\w\-\.]+)\s+([\w\-\.\+]+)", line.strip())
            if m:
                mod_name = m.group(1)
                mod_ver = m.group(2)
                # Ignorar entradas genéricas
                if mod_name.lower() in ["java", "minecraft"]:
                    continue
                mods.add(mod_name)
                if mod_name not in mod_details:
                    mod_details[mod_name] = {}
                if mod_ver:
                    mod_details[mod_name]["version"] = mod_ver
    # 2. "Loaded configuration file for X:"
    for line in log_lines:
        m = re.search(r"Loaded configuration file for ([\w\-]+):", line)
        if m:
            mod_name = m.group(1)
            mods.add(mod_name)
            if mod_name not in mod_details:
                mod_details[mod_name] = {}
    # 3. Mods explícitos por nombre
    explicit_mods = ["Lithium", "Sodium", "Iris", "Krypton", "Indium", "ModMenu", "MoreCulling", "SodiumExtra", "FabricSkyBoxes", "WorldEdit"]
    for line in log_lines:
        for mod in explicit_mods:
            if mod.lower() in line.lower():
                mods.add(mod)
                if mod not in mod_details:
                    mod_details[mod] = {}
    # 3b. Mods detectados por Entrypoint (Fabric/Lunar)
    # Ejemplo: Found Entrypoint(main) net.fabricmc.fabric.impl.lookup.ApiLookupImpl
    entrypoint_pattern = re.compile(r"Found Entrypoint\(.*\) ([\w\.]+)\.([A-Z][\w]+)")
    for line in log_lines:
        m = entrypoint_pattern.search(line)
        if m:
            # Heurística: tomar el penúltimo fragmento del paquete como nombre de mod si es posible
            package_path = m.group(1)
            class_name = m.group(2)
            # Dividir el paquete por puntos
            parts = package_path.split('.')
            # Buscar el nombre de mod más probable
            mod_candidate = None
            # Si hay un fragmento tipo 'mods.<modname>' o 'mod.<modname>'
            for i, part in enumerate(parts):
                if part in ("mods", "mod") and i+1 < len(parts):
                    mod_candidate = parts[i+1]
                    break
            # Si no, tomar el último fragmento que no sea fabricmc/fabric/impl/client/etc
            if not mod_candidate:
                skip = {"net", "fabricmc", "fabric", "impl", "client", "main", "shared", "exampleinits", "init", "initializer", "indigo", "networking", "screenhandler", "event", "lookup", "handler", "convention", "attachment", "router", "sync", "conditions", "invoker", "base", "v0", "v1", "v2", "common", "customingredientsync", "customingredientinit", "legacyhandler", "lootinitializer", "resourceconditionsimpl", "packagemanager", "modinitializer", "pipeline", "renderingcallbackinvoker"}
                filtered = [p for p in parts if p not in skip]
                if filtered:
                    mod_candidate = filtered[-1]
            # Si aún no, usar el class_name
            if not mod_candidate:
                mod_candidate = class_name
            # Evitar duplicados y nombres genéricos
            if mod_candidate and len(mod_candidate) > 2 and mod_candidate.lower() not in skip:
                mods.add(mod_candidate)
                if mod_candidate not in mod_details:
                    mod_details[mod_candidate] = {}
    # 4. Fabric/Forge mods en ResourceManager
    for line in log_lines:
        m = re.search(r"fabric \(([^)]+)\)", line)
        if m:
            for mod in m.group(1).split(","):
                mod_name = mod.strip().split()[0]
                mods.add(mod_name)
                if mod_name not in mod_details:
                    mod_details[mod_name] = {}
    # 5. Forge/Fabric mods en "added by mods [...]"
    for line in log_lines:
        mod_match = re.findall(r"added by mods \[([^\]]+)\]", line)
        for group in mod_match:
            for mod in group.split(","):
                mod_name = mod.strip()
                mods.add(mod_name)
                if mod_name not in mod_details:
                    mod_details[mod_name] = {}
    # 6. Mods en rutas de archivos .jar
    for line in log_lines:
        jar_matches = re.findall(r"mods/([\w\-]+)-[\d\w.\-+]+\.jar", line)
        for mod_name in jar_matches:
            mods.add(mod_name)
            if mod_name not in mod_details:
                mod_details[mod_name] = {}
    # 7. Mods en mensajes de compatibilidad, inicialización, pipeline, etc.
    for line in log_lines:
        # Ejemplo: "[main/INFO]: Mod 'Sodium' initialized"
        m = re.search(r"Mod '([\w\-]+)' initialized", line)
        if m:
            mod_name = m.group(1)
            mods.add(mod_name)
            if mod_name not in mod_details:
                mod_details[mod_name] = {}
        # Ejemplo: "Compatibility level set to JAVA_17 by mod 'Krypton'"
        m2 = re.search(r"by mod '([\w\-]+)'", line)
        if m2:
            mod_name = m2.group(1)
            mods.add(mod_name)
            if mod_name not in mod_details:
                mod_details[mod_name] = {}
        # Ejemplo: "Pipeline for mod: Sodium"
        m3 = re.search(r"Pipeline for mod: ([\w\-]+)", line)
        if m3:
            mod_name = m3.group(1)
            mods.add(mod_name)
            if mod_name not in mod_details:
                mod_details[mod_name] = {}
    # 8. Mods en advertencias o errores relacionados con mods
    for line in log_lines:
        m = re.search(r"as rule '.*' \(added by mods \[([\w\-, ]+)\]\)", line)
        if m:
            for mod_name in m.group(1).split(","):
                mod_name = mod_name.strip()
                mods.add(mod_name)
                if mod_name not in mod_details:
                    mod_details[mod_name] = {}
    # Convertir a lista de dicts y separar dependencias
    mod_list = []
    dep_list = []
    for mod in mods:
        entry = {"name": mod}
        entry.update(mod_details.get(mod, {}))
        if is_dependency(mod):
            dep_list.append(entry)
        else:
            mod_list.append(entry)
    return {
        "mods": sorted(mod_list, key=lambda x: x["name"]),
        "dependencies": sorted(dep_list, key=lambda x: x["name"])
    }

def extract_client(log_lines: List[str]) -> str:
    for line in log_lines:
        # Buscar varias formas de identificar Lunar Client
        if re.search(r"lunar ?client", line, re.IGNORECASE):
            return "LunarClient"
        if re.search(r"\[LC\]", line) or re.search(r"\[LC ", line) or re.search(r"LUNARCLIENT_STATUS", line):
            return "LunarClient"
        if re.search(r"lunar", line, re.IGNORECASE) and ("client" in line.lower() or "[lc" in line.lower()):
            return "LunarClient"
        if re.search(r"fabric loader", line, re.IGNORECASE):
            return "Fabric"
        if re.search(r"forge", line, re.IGNORECASE):
            return "Forge"
    return "Vanilla"  # Si no se detecta ninguno, asumir Vanilla

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
    mods_result = extract_mods(log_lines)
    return {
        "player": player,
        "mc_version": mc_version,
        "player_with_version": player_with_version,
        "mods": mods_result["mods"],
        "dependencies": mods_result["dependencies"],
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



