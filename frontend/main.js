const fs = require("fs");
const path = require("path");
const url = require("url");
const { app, dialog, BrowserWindow } = require("electron");
const { spawn } = require("child_process");
let backendProcess = null;
let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
    },
  });

  let loadUrl;
  if (app.isPackaged) {
    // now load the static export
    loadUrl = `file://${path.join(app.getAppPath(), "out/index.html")}`;
  } else {
    // In development, load from Next.js dev server
    loadUrl = process.env.ELECTRON_START_URL || "http://localhost:3000";
  }
  mainWindow.loadURL(loadUrl).catch((err) => {
    console.error("[Electron] Error loading URL:", loadUrl, err);
    const loadErrorMsg = `Failed to load URL: ${loadUrl}. Error: ${err.message}`;
    if (app.isReady()) {
      dialog.showErrorBox("Load Error", loadErrorMsg);
    } else {
      app.once("ready", () => dialog.showErrorBox("Load Error", loadErrorMsg));
    }
  });

  if (!app.isPackaged) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function startBackend() {
  if (backendProcess) {
    console.log("[Electron] Backend process appears to be already running.");
    return;
  }

  let executableName = "ses_backend";

  const devBackendInfoPath = path.join(__dirname, "packed_backend_info.json");
  const prodBackendInfoPath = path.join(
    app.getAppPath(),
    "packed_backend_info.json"
  );
  let actualInfoPath = app.isPackaged
    ? prodBackendInfoPath
    : devBackendInfoPath;

  if (fs.existsSync(actualInfoPath)) {
    try {
      const backendInfo = JSON.parse(fs.readFileSync(actualInfoPath, "utf-8"));
      if (backendInfo.executableName) {
        executableName = backendInfo.executableName;
      }
      console.log(
        "[Electron] Using backend executable name from info file:",
        executableName
      );
    } catch (e) {
      console.error(
        "[Electron] Error reading or parsing packed_backend_info.json:",
        e.message
      );
    }
  } else {
    console.warn(
      "[Electron] packed_backend_info.json not found at:",
      actualInfoPath,
      ". Using default executable name."
    );
  }

  const prodResourcesBaseDir = path.join(process.resourcesPath, "dist_backend");
  const devResourcesBaseDir = path.join(
    __dirname,
    "../../backend/dist/ses_backend"
  );

  const resourcesBaseDir = app.isPackaged
    ? prodResourcesBaseDir
    : devResourcesBaseDir;
  let backendExecutablePath = path.join(resourcesBaseDir, executableName);

  if (process.platform === "win32") {
    backendExecutablePath += ".exe";
  }

  console.log(
    "[Electron] Attempting to spawn backend. Path:",
    backendExecutablePath
  );

  if (fs.existsSync(backendExecutablePath)) {
    backendProcess = spawn(backendExecutablePath, [], {
      stdio: "pipe",
      windowsHide: true,
    });
    const currentPid = backendProcess.pid;

    backendProcess.stdout.on("data", (d) =>
      console.log("[Backend STDOUT]", d.toString().trim())
    );
    backendProcess.stderr.on("data", (d) =>
      console.error("[Backend STDERR]", d.toString().trim())
    );

    backendProcess.on("close", (code) => {
      console.log(
        `[Backend Process] Exited with code: ${code}, PID: ${currentPid}`
      );
      if (backendProcess && backendProcess.pid === currentPid) {
        backendProcess = null;
      }
    });
    backendProcess.on("error", (err) => {
      console.error(
        `[Backend Process] Spawn error: ${err.message}, PID: ${currentPid}`
      );
      if (backendProcess && backendProcess.pid === currentPid) {
        backendProcess = null;
      }
    });
    console.log("[Electron] Backend process spawn initiated. PID:", currentPid);
  } else {
    console.error(
      "[Electron] CRITICAL: Backend executable was NOT FOUND at the expected path:",
      backendExecutablePath
    );
    const errorMessage = `Critical Error: Backend executable not found.\nPath: ${backendExecutablePath}\n\nThe application cannot function correctly. Please check the build process.`;
    if (app.isReady()) {
      dialog.showErrorBox("Backend Initialization Failed", errorMessage);
    } else {
      app.once("ready", () =>
        dialog.showErrorBox("Backend Initialization Failed", errorMessage)
      );
    }
  }
}

function killBackend() {
  if (backendProcess) {
    console.log(
      "[Electron] Attempting to kill backend process. PID:",
      backendProcess.pid
    );
    const killed = backendProcess.kill();
    console.log(
      killed
        ? "[Electron] Kill signal sent successfully."
        : "[Electron] Failed to send kill signal (process might have already exited)."
    );
    backendProcess = null;
  } else {
    console.log("[Electron] No active backend process to kill.");
  }
}

app.whenReady().then(() => {
  createWindow();
  startBackend();

  app.on("activate", function () {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", function () {
  if (process.platform !== "darwin") {
    killBackend();
    app.quit();
  }
});

app.on("will-quit", () => {
  killBackend();
});
