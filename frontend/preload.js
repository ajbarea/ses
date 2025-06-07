// frontend/preload.js
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  onBackendError: (callback) => ipcRenderer.on("backend-error", (_event, error) => callback(error)),
  removeBackendErrorListeners: () => ipcRenderer.removeAllListeners("backend-error"),
});
