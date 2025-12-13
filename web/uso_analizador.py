# uso_analizador.py
"""
Ejemplo de uso: detección automática de hacks/mods ilegales en logs usando el modelo entrenado y la lista de mods prohibidos de la BD.
"""

# Analizador mejorado: muestra mods y cliente detectado
import os
from analyze_mc_log_utils import analyze_log_lines

log_path = 'c:/Users/pabli/OneDrive/Documentos/latest.log'
if not os.path.exists(log_path):
    log_path = 'c:/Users/pabli/Downloads/latest.log'

with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

result = analyze_log_lines(lines)

print(f"Jugador: {result['player']}")
print(f"Versión de Minecraft: {result['mc_version']}")
print(f"Cliente detectado: {result['client']}")
print("Mods detectados:")
for mod in result['mods']:
    if 'version' in mod:
        print(f"- {mod['name']} {mod['version']}")
    else:
        print(f"- {mod['name']}")
if result['errors']:
    print("Errores detectados en el log:")
    for err in result['errors']:
        print(f"  {err}")
