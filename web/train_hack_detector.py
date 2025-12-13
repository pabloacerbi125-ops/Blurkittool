# train_hack_detector.py
"""
Script para entrenar un modelo de detección de mods/hacks prohibidos en logs de Minecraft.
"""
import sqlite3
import random
import pickle
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Extraer mods prohibidos de la base de datos SQLite
DB_PATH = 'web/instance/blurkit.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("SELECT name FROM mods WHERE status='prohibido'")
prohibited_mods = [row[0] for row in cursor.fetchall()]
conn.close()


# 2. Cargar logs normales (sin hacks) desde varios archivos
def load_log_lines(*filepaths):
    lines = []
    for path in filepaths:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"[WARN] No se pudo leer {path}: {e}")
    return lines

# Puedes agregar más archivos de logs normales aquí
normal_logs = load_log_lines('web/logs_normales.txt', 'c:/Users/pabli/OneDrive/Documentos/latest.log')


# 3. Generar ejemplos de logs con hacks (simulados)
hack_logs = []
for mod in prohibited_mods:
    for _ in range(10):  # Genera 10 ejemplos por mod
        hack_logs.append(f"[INFO]: Loading mod: {mod}")
        hack_logs.append(f"[WARN]: Detected prohibited mod: {mod}")
        hack_logs.append(f"[ERROR]: Player tried to use {mod}")
        hack_logs.append(f"[LC] Detected forbidden mod: {mod}")
        hack_logs.append(f"[LUNARCLIENT] {mod} is not allowed!")


# 4. Preparar dataset
X = normal_logs + hack_logs
y = [0] * len(normal_logs) + [1] * len(hack_logs)

if len(normal_logs) == 0 or len(hack_logs) == 0:
    raise ValueError("No hay suficientes ejemplos de logs normales o de hacks para entrenar el modelo.")


# 5. Vectorizar y entrenar modelo
vectorizer = TfidfVectorizer(ngram_range=(1,2), max_features=1000, lowercase=True)
X_vect = vectorizer.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(X_vect, y, test_size=0.2, random_state=42, stratify=y)
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)


# 6. Evaluar
print("\nReporte de clasificación del modelo:")
print(classification_report(y_test, clf.predict(X_test)))


# 7. Guardar modelo y vectorizador
with open('web/hack_detector_model.pkl', 'wb') as f:
    pickle.dump({'model': clf, 'vectorizer': vectorizer}, f)

print('\nModelo entrenado y guardado en web/hack_detector_model.pkl')
