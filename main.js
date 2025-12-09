const { app, BrowserWindow } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let flaskProcess = null;
let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    },
    title: 'BlurkitTool',
    autoHideMenuBar: true
  });

  // Esperar a que Flask inicie antes de cargar
  setTimeout(() => {
    mainWindow.loadURL('http://127.0.0.1:5000');
  }, 2000);

  mainWindow.on('closed', () => {
    mainWindow = null;
    killFlaskProcess();
  });
}

function killFlaskProcess() {
  if (!flaskProcess) return;
  
  try {
    if (process.platform === 'win32') {
      // En Windows, usar taskkill para matar el proceso y sus hijos
      const { execSync } = require('child_process');
      try {
        execSync(`taskkill /pid ${flaskProcess.pid} /T /F`, { stdio: 'ignore' });
      } catch (e) {
        // Si falla, intentar matar por nombre
        try {
          execSync('taskkill /IM BlurkitTool.exe /F', { stdio: 'ignore' });
        } catch (e2) {
          console.error('Error killing Flask process');
        }
      }
    } else {
      flaskProcess.kill('SIGKILL');
    }
  } catch (e) {
    console.error('Error in killFlaskProcess:', e);
  }
  flaskProcess = null;
}

function startFlask() {
  // Buscar el ejecutable de Flask generado por PyInstaller
  const isDev = !app.isPackaged;
  const flaskExePath = isDev 
    ? path.join(__dirname, 'dist', 'BlurkitTool.exe')
    : path.join(process.resourcesPath, 'BlurkitTool.exe');
  
  console.log(`Starting Flask from: ${flaskExePath}`);
  
  flaskProcess = spawn(flaskExePath, ['--no-browser'], {
    windowsHide: true,
    detached: false  // Importante: no detach para poder matar el proceso
  });

  flaskProcess.stdout.on('data', (data) => {
    console.log(`Flask: ${data}`);
  });

  flaskProcess.stderr.on('data', (data) => {
    console.error(`Flask Error: ${data}`);
  });

  flaskProcess.on('close', (code) => {
    console.log(`Flask process exited with code ${code}`);
  });
}

app.on('ready', () => {
  startFlask();
  createWindow();
});

app.on('window-all-closed', () => {
  killFlaskProcess();
  app.quit();
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});

app.on('before-quit', () => {
  killFlaskProcess();
});

app.on('will-quit', () => {
  killFlaskProcess();
});
