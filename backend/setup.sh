#!/bin/bash
# Quick setup script for different installation types

set -e

show_usage() {
    echo "Usage: $0 [base|dev|gpu|full]"
    echo ""
    echo "Installation types:"
    echo "  base  - Core runtime dependencies only (~200MB)"
    echo "  dev   - Base + development tools (testing, building)"
    echo "  gpu   - Base + GPU-enabled PyTorch (~2.7GB)"
    echo "  full  - Base + dev + GPU (everything)"
    echo ""
    echo "Examples:"
    echo "  $0 base    # For production deployment"
    echo "  $0 dev     # For development and testing"
    echo "  $0 gpu     # For ML training with GPU"
    echo "  $0 full    # For complete development setup"
    exit 1
}

install_type=${1:-base}

case $install_type in
    base)
        echo "📦 Installing base dependencies..."
        pip install --upgrade pip
        pip install -r requirements-base.txt
        echo "✅ Base installation complete (~200MB)"
        ;;
    dev)
        echo "📦 Installing base + development dependencies..."
        pip install --upgrade pip
        pip install -r requirements-base.txt -r requirements-dev.txt
        echo "✅ Development installation complete"
        ;;
    gpu)
        echo "📦 Installing base + GPU dependencies..."
        pip install --upgrade pip
        pip install -r requirements-base.txt -r requirements-gpu.txt
        echo "✅ GPU installation complete (~2.7GB)"
        ;;
    full)
        echo "📦 Installing all dependencies..."
        pip install --upgrade pip
        pip install -r requirements-base.txt -r requirements-dev.txt -r requirements-gpu.txt
        echo "✅ Full installation complete"
        ;;
    *)
        echo "❌ Unknown installation type: $install_type"
        show_usage
        ;;
esac

echo ""
echo "🔍 Verifying installation..."
python -c "
import sys
success = True

# Test core imports
try:
    import fastapi, uvicorn, pandas, sklearn, torch
    print('✅ Core ML/web dependencies working')
except ImportError as e:
    print(f'❌ Core dependency missing: {e}')
    success = False

# Test CLIPS (optional)
try:
    import clips
    print('✅ CLIPS module available')
except ImportError:
    print('⚠️  CLIPS module not available (optional)')

# Test platform-specific
try:
    import platform
    if platform.system() == 'Windows':
        import wmi
        print('✅ Windows-specific modules working')
except ImportError as e:
    print(f'⚠️  Platform-specific module issue: {e}')

if not success:
    sys.exit(1)
print('✅ Installation verification complete')
"

echo ""
echo "🚀 Ready to go! Run your application with:"
echo "   python main.py"
