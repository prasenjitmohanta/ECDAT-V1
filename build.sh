#!/bin/bash
# ==============================================================================
#  ECDAT — One-Click Cross-Platform Build Script (macOS / Linux)
# ==============================================================================

set -e

# ANSI Color Codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}"
echo "======================================================================"
echo "    ECDAT — Enterprise Cryptographic Discovery & Assessment Tool     "
echo "    Cross-Platform Build & Verification System (macOS / Linux)       "
echo "======================================================================"
echo -e "${NC}"

# 1. Detect OS
OS_NAME="$(uname -s)"
echo -e "${BLUE}[1/5] Detecting Operating System:${NC} ${OS_NAME} ($(uname -m))"

# 2. Check Compiler & CMake
echo -e "${BLUE}[2/5] Checking Build Tools...${NC}"
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}[ERROR] CMake is not installed!${NC}"
    if [ "$OS_NAME" = "Darwin" ]; then
        echo "Please install CMake via Homebrew: brew install cmake"
    else
        echo "Please install CMake: sudo apt install cmake (Ubuntu) or sudo dnf install cmake (Fedora)"
    fi
    exit 1
fi
echo -e "  ✓ CMake found: $(cmake --version | head -n 1)"

# Check C++ Compiler
if [ -n "$CXX" ] && command -v "$CXX" &> /dev/null; then
    COMPILER="$CXX"
elif command -v clang++ &> /dev/null; then
    COMPILER="clang++"
elif command -v g++ &> /dev/null; then
    COMPILER="g++"
else
    echo -e "${RED}[ERROR] No suitable C++ compiler (clang++ or g++) found!${NC}"
    exit 1
fi
echo -e "  ✓ C++ Compiler found: ${COMPILER}"

# 3. Check Python & ML Dependencies
echo -e "${BLUE}[3/5] Checking Python ML Environment...${NC}"
PYTHON_BIN=""
for py in "/Users/prasenjit/miniconda3/bin/python3" "python3" "/usr/bin/python3" "/opt/homebrew/bin/python3"; do
    if command -v "$py" &> /dev/null; then
        if "$py" -c "import joblib, sklearn, numpy, pandas" 2>/dev/null; then
            PYTHON_BIN="$py"
            break
        elif [ -z "$PYTHON_BIN" ]; then
            PYTHON_BIN="$py"
        fi
    fi
done

if [ -n "$PYTHON_BIN" ]; then
    echo -e "  ✓ Python interpreter: ${PYTHON_BIN}"
    if ! "$PYTHON_BIN" -c "import joblib, sklearn, numpy, pandas" 2>/dev/null; then
        echo -e "  ${YELLOW}Installing required ML packages (joblib, scikit-learn, numpy, pandas)...${NC}"
        "$PYTHON_BIN" -m pip install -r requirements.txt || true
    fi
else
    echo -e "  ${YELLOW}[WARNING] Python 3 not found. Stage 3 ML inference requires Python with scikit-learn.${NC}"
fi

# 4. Configure CMake
echo -e "${BLUE}[4/5] Configuring CMake Project...${NC}"
mkdir -p build

# Determine Qt prefix path on macOS if using Homebrew
CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
if [ "$OS_NAME" = "Darwin" ]; then
    if [ -d "/opt/homebrew/opt/qt6" ]; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt6"
    elif [ -d "/opt/homebrew/opt/qt@6" ]; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt@6"
    elif [ -d "/usr/local/opt/qt6" ]; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DCMAKE_PREFIX_PATH=/usr/local/opt/qt6"
    fi
fi

cmake -B build ${CMAKE_FLAGS}

# 5. Build Binary
echo -e "${BLUE}[5/5] Compiling ECDAT Targets...${NC}"
NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
cmake --build build -j${NPROC}

echo -e "\n${BOLD}${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}  ✓ BUILD SUCCESSFUL!                                                  ${NC}"
echo -e "${BOLD}${GREEN}======================================================================${NC}\n"

if [ "$OS_NAME" = "Darwin" ]; then
    APP_PATH="build/ecdat_app.app/Contents/MacOS/ecdat_app"
    echo -e "To launch ECDAT GUI:"
    echo -e "  ${BOLD}open build/ecdat_app.app${NC}  or  ${BOLD}./${APP_PATH}${NC}\n"
else
    APP_PATH="build/ecdat_app"
    echo -e "To launch ECDAT GUI:"
    echo -e "  ${BOLD}./build/ecdat_app${NC}\n"
fi

if [ -t 0 ]; then
    read -p "Would you like to launch ECDAT now? (y/N): " choice
    case "$choice" in 
      y|Y ) 
        if [ "$OS_NAME" = "Darwin" ]; then
            open build/ecdat_app.app
        else
            ./build/ecdat_app &
        fi
        ;;
      * ) echo "Launch skipped.";;
    esac
fi
