# BlurkitTool

Herramienta de escritorio para gestionar y analizar mods de Blurkit. La aplicación permite administrar listas de mods permitidos y bloqueados, revisar registros del juego y mantener una base de control ordenada para uso diario.

## Características

- Gestión de mods con categorías y plataformas
- Clasificación automática entre mods permitidos y bloqueados
- Análisis de archivos de registro para detectar mods activos
- Búsqueda por nombre, categoría o plataforma
- Interfaz visual con estilo oscuro
- Aplicación de escritorio compatible con Windows

## Instalación

### Opción 1: Ejecutable
1. Descarga el archivo ejecutable desde la sección de releases del proyecto.
2. Ejecuta el archivo sin necesidad de instalar nada adicional.
3. La aplicación queda lista para su uso.

### Opción 2: Desde el código fuente

#### Requisitos
- Python 3.14+
- Node.js 24+
- npm 11+

#### Pasos

1. Clona el repositorio:
```bash
git clone <URL_DEL_REPOSITORIO>
cd BlurkitTool
```

2. Configura el entorno de Python:
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r web/requirements.txt
```

3. Instala las dependencias de Node:
```bash
npm install
```

4. Genera el ejecutable de Flask:
```bash
pyinstaller BlurkitTool.spec
```

5. Compila la aplicación Electron:
```bash
npm run build-win
```

El ejecutable final se generará en la carpeta de distribución del proyecto.

## Uso

### Modo desarrollo
```bash
cd web
python app.py
```

La aplicación puede abrirse en el navegador en `http://localhost:5000`.

## Base de datos y despliegue

Para mantener la información en un entorno más estable y evitar depender de una copia local, se puede utilizar PostgreSQL en un servicio externo. La idea es conservar la base de datos en un entorno gestionado y migrar los datos desde SQLite una sola vez.

### 1) Crear la base de datos
- Crear una instancia PostgreSQL en el servicio de despliegue elegido.
- Registrar la URL de conexión de la base de datos.

### 2) Configurar la aplicación
- Añadir la variable de entorno `DATABASE_URL` con la URL interna o de conexión apropiada para el entorno de la aplicación.

### 3) Migración de SQLite a PostgreSQL
1. Verificar que las dependencias estén instaladas:
```bash
pip install -r web/requirements.txt
```
2. Preparar la URL de conexión de PostgreSQL.
3. Ejecutar la migración desde la carpeta `web/`:
```powershell
$env:DATABASE_URL = "<DATABASE_URL>"
python migrate_sqlite_to_postgres.py --sqlite instance/blurkit.db
```
4. Cuando termine la migración, dejar la aplicación apuntando a la URL final correcta del entorno.

Notas:
- La migración asume que la base de datos destino en PostgreSQL está vacía.
- En algunos casos puede requerirse una opción de sobrescritura si se desea reemplazar contenido existente.

## Funcionalidades

### Gestión de mods
- Agregar mods con nombre, categoría, plataforma y estado
- Editar cualquier campo existente
- Eliminar elementos con confirmación
- Filtrar por criterios de búsqueda

### Análisis de logs
- Cargar archivos de log del juego
- Pegar texto directamente desde el portapapeles
- Detectar mods activos automáticamente
- Personalizar patrones de búsqueda desde la configuración

## Tecnologías

- Backend: Flask 3.1.2 (Python)
- Frontend: Bootstrap 5.3.2, JavaScript vanilla
- Desktop: Electron 28.3.3
- Empaquetado: PyInstaller 6.17.0, electron-builder 24.13.3
- Datos: JSON y soporte para bases de datos externas

## Estructura del proyecto

```text
BlurkitTool/
├── web/                    # Aplicación Flask
│   ├── app.py             # Rutas y lógica principal
│   ├── core.py            # Funciones de análisis
│   ├── templates/         # Plantillas HTML
│   └── static/           # CSS y assets
├── main.js                # Proceso principal de Electron
├── run_app.py             # Entry point para PyInstaller
├── package.json           # Configuración de Electron
├── BlurkitTool.spec       # Configuración de PyInstaller
├── mods.json              # Base de datos de mods
├── README.md              # Documentación del proyecto
└── ...
```

## Solución de problemas

### La aplicación no abre
- Verifica que no haya otra instancia ejecutándose.
- Si es necesario, cierra procesos activos del ejecutable.

### Los datos no se guardan
- Asegúrate de que el archivo de datos se encuentre en la misma carpeta que el ejecutable.
- Comprueba que la carpeta tenga permisos de escritura.

### Error al cargar logs
- Comprueba que el archivo sea un log válido del juego.
- Revisa que los patrones configurados coincidan con el formato del registro.

## Licencia

Este proyecto es de código abierto y puede utilizarse, modificarse y adaptarse según sea necesario.

## Contribuciones

Las contribuciones son bienvenidas. Si se encuentra un problema o se desea mejorar la funcionalidad, se puede trabajar sobre una rama de desarrollo y abrir una solicitud de cambios una vez validado el resultado.

## Capturas y ejemplos

Se pueden añadir capturas de pantalla o ejemplos de uso en esta sección según lo requiera la distribución final del proyecto.
