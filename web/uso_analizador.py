# uso_analizador.py
"""
Ejemplo de uso: detección automática de hacks/mods ilegales en logs usando el modelo entrenado y la lista de mods prohibidos de la BD.
"""
from ml_integration import MLLogModel
from log_analyzer import MinecraftLogAnalyzer
import pickle

# Cargar lista de mods prohibidos
with open('web/prohibited_mods.txt', 'r', encoding='utf-8') as f:
    hacks = [line.strip() for line in f if line.strip()]

# Cargar modelo entrenado
with open('web/hack_detector_model.pkl', 'rb') as f:
    data = pickle.load(f)
    clf = data['model']
    vectorizer = data['vectorizer']
ml_model = MLLogModel(clf, vectorizer)

# Instanciar el analizador
analyzer = MinecraftLogAnalyzer(hacks, regex_patterns=[], ml_model=ml_model)

# Analizar un log (puedes cambiar la ruta al log que quieras analizar)
with open('c:/Users/pabli/OneDrive/Documentos/latest.log', 'r', encoding='utf-8') as f:
    lines = f.readlines()
results = analyzer.parse_log(lines)

print(f"Se detectaron {len(results)} posibles hacks/mods ilegales:")
for r in results:
    print(r)
