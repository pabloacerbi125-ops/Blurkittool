# ml_integration.py
"""
Carga el modelo entrenado y lo integra con el analizador de logs para detección automática.
"""
import pickle


MODEL_PATH = 'web/hack_detector_model.pkl'

def load_ml_model(model_path=MODEL_PATH):
    """Carga el modelo ML y el vectorizador desde disco solo cuando se llama."""
    with open(model_path, 'rb') as f:
        data = pickle.load(f)
        clf = data['model']
        vectorizer = data['vectorizer']
    return clf, vectorizer

class MLLogModel:
    def __init__(self, clf, vectorizer):
        self.clf = clf
        self.vectorizer = vectorizer
    def predict(self, lines):
        X = self.vectorizer.transform(lines)
        return self.clf.predict(X)

# Ejemplo de integración:
# hacks = [...]  # Lista de mods prohibidos
# regex_patterns = [...]  # Patrones adicionales si quieres
# ml_model = MLLogModel(clf, vectorizer)
# analyzer = MinecraftLogAnalyzer(hacks, regex_patterns, ml_model)
# with open('ruta/del/log_a_analizar.log', 'r', encoding='utf-8') as f:
#     lines = f.readlines()
# results = analyzer.parse_log(lines)
# print(results)
