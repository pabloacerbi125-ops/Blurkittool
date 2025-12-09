# 🎮 BlurkitModsTool

Herramienta de escritorio para gestionar y analizar mods de Blurkit. Aplicación multiplataforma desarrollada con Flask + Electron que permite administrar listas de mods prohibidos/permitidos y analizar logs del juego.

## ✨ Características

- **Gestión de Mods**: Agregar, editar y eliminar mods con categorías y plataformas
- **Clasificación Automática**: Organiza mods en prohibidos y permitidos
- **Análisis de Logs**: Carga y analiza archivos de log del juego para detectar mods
- **Búsqueda Inteligente**: Busca mods por nombre, categoría o plataforma
- **Interfaz Moderna**: Diseño dark theme con estilo gaming
- **App de Escritorio**: Empaquetada como aplicación nativa de Windows

## 🚀 Instalación

### Opción 1: Ejecutable (Recomendado)
1. Descarga `BlurkitTool 1.0.0.exe` desde [Releases](https://github.com/pabloacerbi125-ops/Blurkittool/releases)
2. Ejecuta el archivo - no requiere instalación
3. ¡Listo para usar!

### Opción 2: Desde el código fuente

#### Requisitos
- Python 3.14+
- Node.js 24+
- npm 11+

#### Pasos

1. **Clona el repositorio**
```bash
git clone https://github.com/pabloacerbi125-ops/Blurkittool.git
cd Blurkittool
```

2. **Configura el entorno Python**
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r web/requirements.txt
```

3. **Instala dependencias de Node**
```bash
npm install
```

4. **Genera el ejecutable de Flask**
```bash
pyinstaller BlurkitTool.spec
```

5. **Compila la aplicación Electron**
```bash
npm run build-win
```

El ejecutable final estará en `dist\BlurkitTool 1.0.0.exe`

## 📖 Uso

### Modo Desarrollo
```bash
cd web
python app.py
```
Abre http://localhost:5000 en tu navegador

### Aplicación de Escritorio
Ejecuta `BlurkitTool 1.0.0.exe` directamente

## 🎯 Funcionalidades

### Gestión de Mods
- **Agregar Mod**: Nombre, categoría, plataforma y estado (prohibido/permitido)
- **Editar Mod**: Modifica cualquier campo de un mod existente
- **Eliminar Mod**: Borra mods con confirmación
- **Búsqueda**: Filtra mods por criterios específicos

### Análisis de Logs
- **Cargar Log**: Sube archivos de log del juego
- **Pegar Log**: Copia y pega contenido directamente
- **Detección Automática**: Identifica mods activos en el juego
- **Edición de Lookup**: Personaliza patrones de detección

## 🛠️ Tecnologías

- **Backend**: Flask 3.1.2 (Python)
- **Frontend**: Bootstrap 5.3.2, JavaScript vanilla
- **Desktop**: Electron 28.3.3
- **Empaquetado**: PyInstaller 6.17.0, electron-builder 24.13.3
- **Datos**: JSON (mods.json)

## 📁 Estructura del Proyecto

```
BlurkitModsTool/
├── web/                    # Aplicación Flask
│   ├── app.py             # Rutas y lógica principal
│   ├── core.py            # Funciones de análisis
│   ├── templates/         # Plantillas HTML
│   └── static/           # CSS y assets
├── main.js                # Proceso principal de Electron
├── run_app.py            # Entry point para PyInstaller
├── package.json          # Configuración de Electron
├── BlurkitTool.spec      # Configuración de PyInstaller
└── mods.json             # Base de datos de mods
```

## 🐛 Solución de Problemas

### La app no abre
- Verifica que no haya otra instancia ejecutándose
- Cierra procesos con: `taskkill /F /IM BlurkitTool.exe`

### Los datos no se guardan
- Asegúrate de que `mods.json` está en la misma carpeta que el .exe
- Verifica permisos de escritura en la carpeta

### Error al cargar logs
- Verifica que el archivo sea un log válido de Blurkit
- Revisa que los patrones en "Editar Lookup" coincidan con tu formato

## 📝 Licencia

Este proyecto es de código abierto. Siéntete libre de usarlo y modificarlo.

## 👤 Autor

**pabloacerbi125-ops**
- GitHub: [@pabloacerbi125-ops](https://github.com/pabloacerbi125-ops)

## 🤝 Contribuir

Las contribuciones son bienvenidas! Si encuentras un bug o tienes una sugerencia:

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/mejora`)
3. Commit tus cambios (`git commit -m 'Añade nueva característica'`)
4. Push a la rama (`git push origin feature/mejora`)
5. Abre un Pull Request

## 🎮 Screenshots

_(Aquí puedes agregar capturas de pantalla de la aplicación)_

---

⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub!