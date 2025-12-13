import sys
from analyze_mc_log_utils import analyze_log_lines

if __name__ == "__main__":
    # Leer log de stdin o archivo
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8", errors="ignore") as f:
            log_lines = f.readlines()
    else:
        print("Pega el log y termina con Ctrl+Z (Windows) o Ctrl+D (Linux/macOS):")
        log_lines = sys.stdin.read().splitlines()
    result = analyze_log_lines(log_lines)
    print("Mods detectados:")
    for mod in result["mods"]:
        print(f"- {mod['name']} {mod.get('version','')}")
    print("\nCliente detectado:", result["client"])
    print("\nJugador:", result["player_with_version"])
    if result["errors"]:
        print("\nErrores detectados:")
        for err in result["errors"]:
            print("-", err)
