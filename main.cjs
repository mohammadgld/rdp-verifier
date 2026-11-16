const { app, BrowserWindow } = require('electron');

let window;
let service;

app.setName('RDP Verifier');
if (process.platform === 'win32') app.setAppUserModelId('RDP.Verifier');

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!window) return;
    if (window.isMinimized()) window.restore();
    window.focus();
  });

  app.whenReady().then(async () => {
    try {
      const { startServer } = await import('./server.mjs');
      service = await startServer({ port: 0, openBrowser: false, outputDirectory: app.getPath('desktop') });
      window = new BrowserWindow({
        title: 'RDP Verifier',
        width: 580,
        height: 420,
        minWidth: 520,
        minHeight: 400,
        backgroundColor: '#f6f8f7',
        show: false,
        autoHideMenuBar: true,
        webPreferences: {
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true,
        },
      });
      window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      window.webContents.on('will-navigate', (event, destination) => {
        if (destination !== service.url && destination !== `${service.url}/`) event.preventDefault();
      });
      window.once('ready-to-show', () => window.show());
      await window.loadURL(service.url);
    } catch (error) {
      console.error(`RDP Verifier could not start: ${error.message}`);
      app.quit();
    }
  });

  app.on('window-all-closed', () => app.quit());
  app.on('before-quit', () => {
    service?.close().catch(() => {});
  });
}
