# log_analyzer.py
"""
Módulo para analizar logs de Minecraft y detectar uso de hacks/clientes ilegales.
"""
import re
from typing import List, Dict


class MinecraftLogAnalyzer:
    def __init__(self, hacks_list: List[str], regex_patterns: List[str] = None, ml_model=None):
        self.hacks_list = [h.lower() for h in hacks_list]
        self.regex_patterns = [re.compile(pat, re.IGNORECASE) for pat in (regex_patterns or [])]
        self.ml_model = ml_model  # Modelo de IA opcional

    def parse_log(self, log_lines: List[str]) -> List[Dict]:
        """Procesa líneas de log y detecta posibles hacks/clientes ilegales usando palabras clave, regex y modelo ML."""
        detections = []
        for line in log_lines:
            lower_line = line.lower()
            # Detección por palabras clave
            for hack in self.hacks_list:
                if hack in lower_line:
                    detections.append({
                        'type': 'keyword',
                        'pattern': hack,
                        'log': line
                    })
            # Detección por patrones regex
            for regex in self.regex_patterns:
                if regex.search(line):
                    detections.append({
                        'type': 'regex',
                        'pattern': regex.pattern,
                        'log': line
                    })
            # Detección por modelo ML (si está disponible)
            if self.ml_model:
                pred = self.ml_model.predict([line])[0]
                if pred == 1:  # 1 = sospechoso
                    detections.append({
                        'type': 'ml',
                        'pattern': 'ML Model',
                        'log': line
                    })
        return detections

# Ejemplo de uso avanzado:
# hacks = ['wurst', 'impact', 'aristois']
# regex_patterns = [r'\[mod\]', r'cheat detected', r'\b(lunar|forge)\b']
# analyzer = MinecraftLogAnalyzer(hacks, regex_patterns)
# with open('server.log', 'r', encoding='utf-8') as f:
#     lines = f.readlines()
# results = analyzer.parse_log(lines)
# print(results)

# Ejemplo de uso:
# hacks = ['wurst', 'impact', 'aristois']
# analyzer = MinecraftLogAnalyzer(hacks)
# with open('server.log', 'r', encoding='utf-8') as f:
#     lines = f.readlines()
# results = analyzer.parse_log(lines)
# print(results)
