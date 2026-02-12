const { app, BrowserWindow } = require('electron');

function createWindow () {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    title: "Path Project",
    webPreferences: {
      nodeIntegration: false,    
      contextIsolation: true,     
      sandbox: false              
    }
  });

  win.loadURL('https://path-project.onrender.com');
  
  win.on('page-title-updated', (e) => e.preventDefault());
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});