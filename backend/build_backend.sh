#!/bin/bash
echo "--- Starting Backend Build ---"
set -e
cd "$(dirname "$0")"

echo "Removing old backend build artifacts..."
rm -rf dist build

echo "Creating/reusing virtual environment .venv_backend_build..."
if [ ! -d ".venv_backend_build" ]; then
  python3 -m venv .venv_backend_build
fi

# activate venv (Linux/macOS vs. Windows)
if [ -f ".venv_backend_build/bin/activate" ]; then
    . .venv_backend_build/bin/activate
elif [ -f ".venv_backend_build/Scripts/activate" ]; then
    . .venv_backend_build/Scripts/activate
else
    echo "Cannot find virtualenv activation script"
    exit 1
fi

echo "Installing/updating dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

# Verify CLIPS installation
python -c "
import sys
try:
    import clips
    print('✅ CLIPS module successfully imported')
except ImportError as e:
    print(f'❌ Failed to import CLIPS: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Unexpected error importing CLIPS: {e}')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    echo "ERROR: CLIPS verification failed. Please check your installation."
    echo "Build will continue, but CLIPS functionality may not work in the packaged app."
fi

echo "Running PyInstaller to build the backend executable..."
PYINSTALLER_WMI_ARG=""
current_os_lower=$(uname -s | tr '[:upper:]' '[:lower:]')
if [[ "$current_os_lower" == "cygwin"* || "$current_os_lower" == "mingw"* || "$current_os_lower" == "msys_nt"* || "$current_os_lower" == "windows_nt" ]] ; then
    echo "BUILD_INFO: Detected Windows-like system. Adding WMI hidden import for PyInstaller."
    PYINSTALLER_WMI_ARG="--hidden-import=wmi"
else
    echo "BUILD_INFO: Detected non-Windows system. WMI hidden import not added."
fi

# Enhanced PyInstaller command with better CLIPS support
pyinstaller --noconfirm --onedir --name ses_backend main.py \
     --paths src \
     --add-data "src:src" \
     --hidden-import="uvicorn.logging" --hidden-import="uvicorn.loops" --hidden-import="uvicorn.loops.auto" \
     --hidden-import="uvicorn.protocols" --hidden-import="uvicorn.protocols.http" --hidden-import="uvicorn.protocols.http.auto" \
     --hidden-import="uvicorn.protocols.websockets" --hidden-import="uvicorn.protocols.websockets.auto" \
     --hidden-import="uvicorn.lifespan" --hidden-import="uvicorn.lifespan.on" \
     --hidden-import="fastapi.applications" --hidden-import="starlette.routing" \
     --hidden-import="starlette.middleware.cors" --hidden-import="starlette.applications" \
     --hidden-import="appdirs" --hidden-import="psutil" \
     --hidden-import="pydantic.v1" --hidden-import="json" --hidden-import="asyncio" \
     --hidden-import="logging.config" --hidden-import="pathlib" \
     --hidden-import="clips" --hidden-import="clips.common" --hidden-import="clips.facts" \
     --hidden-import="clips.functions" --collect-binaries clipspy \
     --collect-all clips \
     --collect-data clipspy \
     ${PYINSTALLER_WMI_ARG}

# Additional debug step to check the packaged executable
echo "Checking for CLIPS in packaged output..."
find dist/ses_backend -name "*clips*" || echo "No CLIPS files found in package"

deactivate
echo "PyInstaller build process complete. Backend executable should be in backend/dist/ses_backend/"
echo "--- Backend Build Finished Successfully ---"
