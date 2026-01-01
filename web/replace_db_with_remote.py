import shutil
import os

# Ruta local de la base de datos
local_db = os.path.join(os.path.dirname(__file__), 'instance', 'blurkit.db')
# Ruta de la base de datos "del host/remoto" (ajusta esta ruta según tu entorno)
remote_db = os.path.join(os.path.dirname(__file__), 'blurkit_remote.db')  # <-- Cambia esto si tu archivo remoto está en otra ruta

# Elimina la base de datos local si existe
if os.path.exists(local_db):
    os.remove(local_db)
    print(f"Eliminada base de datos local: {local_db}")
else:
    print(f"No existía base de datos local: {local_db}")

# Copia la base de datos remota a la ubicación local
shutil.copy(remote_db, local_db)
print(f"Copiada base de datos remota ({remote_db}) a local ({local_db})")
