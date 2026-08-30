# 🛡️ ECDAT — Enterprise Cryptographic Discovery & Assessment Tool

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20%20%2F%2023-blue.svg)](https://en.cppreference.com/)
[![Qt Version](https://img.shields.io/badge/Qt-6.5%2B-green.svg)](https://www.qt.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/)
[![CBOM Standard](https://img.shields.io/badge/CBOM-CycloneDX%20v1.5-purple.svg)](https://cyclonedx.org/)

**ECDAT** is a high-performance, cross-platform enterprise cryptographic auditor, post-quantum risk analyzer, and **Cryptographic Bill of Materials (CBOM)** generation platform. It automatically inspects enterprise codebases, binary firmware, and raw ciphertexts to identify classical cryptographic vulnerabilities, compute quantum migration timelines via **Mosca's Theorem**, and generate compliant **CycloneDX v1.5 CBOMs**.

---

## 📑 Table of Contents
- [🌟 Key Capabilities](#-key-capabilities)
- [🏗️ Multi-Stage Architecture](#️-multi-stage-architecture)
- [📋 System Requirements](#-system-requirements)
- [⚡ Quick Start (One-Click Build)](#-quick-start-one-click-build)
- [💻 Detailed Step-by-Step Installation](#-detailed-step-by-step-installation)
  - [🍎 macOS (Apple Silicon & Intel)](#-macos-apple-silicon--intel)
  - [🐧 Linux (Ubuntu / Debian / Fedora / Arch)](#-linux-ubuntu--debian--fedora--arch)
  - [🪟 Windows (MSVC / MinGW)](#-windows-msvc--mingw)
- [🚀 How to Run & Audit](#-how-to-run--audit)
- [📊 CBOM & Report Exports](#-cbom--report-exports)
- [🔧 Troubleshooting & FAQ](#-troubleshooting--faq)

---

## 🌟 Key Capabilities

1. **Stage 1: AST Semantic Code Parser (Tree-Sitter)**:
   - Deep structural AST analysis for C/C++, Python, Java, and Go.
   - Dynamic parameter extraction for key lengths (`RSA-1024`, `RSA-2048`, `RSA-4096`, `AES-128`, `AES-256`) and elliptic curves (`NIST P-256`, `NIST P-384`, `NIST P-521`, `Curve25519`).
   - Deterministic **100.0% confidence** detection.

2. **Stage 2: YARA Signature Engine**:
   - Vectorized binary inspection scanning firmware and compiled objects (`.so`, `.dll`, `.exe`, `.dylib`, `.elf`).
   - Discovers hardcoded keys, certificate PEMs, AES forward/inverse S-Boxes, DES permutation matrices, and ChaCha20 constant vectors (`expand 32-byte k`).

3. **Stage 3: NIST SP 800-22 Machine Learning Cipher Triage**:
   - Vectorized Random Forest classifier trained on 46 length-invariant NIST randomness features.
   - Accurately classifies raw, unlabelled ciphertext blobs (`3DES`, `AES`, `Blowfish`, `CAST`, `RC4`, `ChaCha20`, `RSA`, `ECC`) with dynamic statistical confidence scores.

4. **Quantum Threat Analysis & Mosca's Theorem Engine**:
   - Evaluates **Mosca’s Theorem** formula ($X + Y > Z$) where:
     - $X$ = Shelf-life / Data retention requirement
     - $Y$ = Migration & Deployment timeline
     - $Z$ = Collapse date (Quantum Breakthrough / Q-Day estimate)
   - Color-coded risk status: 🔴 **CRITICAL ALERT** ($X+Y > Z$), 🟡 **WARNING** ($X+Y \approx Z$), 🟢 **SAFE** ($X+Y < Z$).
   - Categorizes threats into **Shor's Algorithm** (Asymmetric collapse) and **Grover's Algorithm** (Symmetric key-halving).

5. **CycloneDX v1.5 CBOM Generator**:
   - Exports cryptographically compliant CycloneDX v1.5 JSON formatted CBOMs, Markdown executive reports, and CSV spreadsheets.

6. **Interactive Dark/Obsidian Qt6 GUI**:
   - 270° Speedometer Risk Gauge with animated needle and glow effects.
   - Deep Asset Inspector detailing CWE IDs, Quantum Threat type, PQC Migration recommendations (NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA).
   - Right-click **"Open with Code Editor"** (VS Code, Cursor, Xcode, Zed, Sublime Text, IntelliJ).
   - Persistent **Scan History** stored locally with search and 1-click reload.

---

## 🏗️ Multi-Stage Architecture

```
                                  ┌────────────────────────┐
                                  │   Target Audit Path    │
                                  └───────────┬────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
          [ Source Code Files ]                              [ Binary / Ciphertext ]
         (.cpp, .c, .py, .java, .go)                         (.bin, .so, .exe, .dat)
                     │                                                 │
                     ▼                                                 ▼
        ┌─────────────────────────┐                       ┌─────────────────────────┐
        │  Stage 1: Tree-Sitter   │                       │  Stage 2: YARA Engine   │
        │   Semantic AST Parser   │                       │   Signature & S-Boxes   │
        └────────────┬────────────┘                       └────────────┬────────────┘
                     │                                                 │  (If Untriaged Blob)
                     │                                                 ▼
                     │                                    ┌─────────────────────────┐
                     │                                    │ Stage 3: Random Forest  │
                     │                                    │  NIST SP 800-22 Triage  │
                     │                                    └────────────┬────────────┘
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              │
                                              ▼
                                ┌───────────────────────────┐
                                │   Mosca Theorem Engine    │
                                │   PQC Recommendation Fix  │
                                └─────────────┬─────────────┘
                                              │
                                              ▼
                      ┌───────────────────────────────────────────────┐
                      │             ECDAT Graphical Hub               │
                      │  • 270° Risk Gauge    • CBOM Inventory Table  │
                      │  • Deep Inspector     • Terminal Console      │
                      │  • Code Editor Reveal • Scan History Database │
                      └───────────────────────────────────────────────┘
```

---

## 📋 System Requirements

| Component | Minimum Requirement | Recommended |
| :--- | :--- | :--- |
| **Operating System** | macOS 12+ / Ubuntu 20.04+ / Windows 10+ | macOS 14+ / Ubuntu 24.04 / Windows 11 |
| **C++ Compiler** | C++20 compliant (`clang++ 14+`, `g++ 11+`, `MSVC 2019+`) | `clang++ 17+` / `g++ 13+` |
| **Build System** | CMake 3.20+ | CMake 3.28+ |
| **GUI Framework** | Qt 6.4+ (Core, Widgets, Charts, Svg, Concurrent) | Qt 6.7+ |
| **Python Engine** | Python 3.10+ (for Stage 3 ML inference) | Python 3.11+ with Miniconda / Virtualenv |
| **Python Libraries** | `joblib`, `scikit-learn`, `numpy`, `pandas`, `scipy` | Listed in `requirements.txt` |

---

## ⚡ Quick Start (One-Click Build)

### 🍎 macOS & 🐧 Linux:
```bash
git clone <repo-url> ECDAT
cd ECDAT
./build.sh
```

### 🪟 Windows:
```bat
git clone <repo-url> ECDAT
cd ECDAT
build.bat
```

---

## 💻 Detailed Step-by-Step Installation

### 🍎 macOS (Apple Silicon & Intel)

1. **Install Prerequisites using Homebrew**:
   ```bash
   brew update
   brew install cmake qt@6 python@3.11
   ```

2. **Install Python ML Dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Configure & Compile with CMake**:
   ```bash
   # Add Qt6 to CMake prefix path
   export CMAKE_PREFIX_PATH="/opt/homebrew/opt/qt6:$CMAKE_PREFIX_PATH"
   
   mkdir -p build
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(sysctl -n hw.ncpu)
   ```

4. **Launch Application**:
   ```bash
   open build/ecdat_app.app
   # Or run binary directly:
   ./build/ecdat_app.app/Contents/MacOS/ecdat_app
   ```

---

### 🐧 Linux (Ubuntu / Debian / Fedora / Arch)

#### Ubuntu / Debian (22.04 LTS, 24.04 LTS):
1. **Install Qt6 & Build Essentials**:
   ```bash
   sudo apt update
   sudo apt install -y build-essential cmake qt6-base-dev qt6-charts-dev qt6-svg-dev \
                       libqt6concurrent6 python3 python3-pip python3-dev
   ```

2. **Install Python ML Packages**:
   ```bash
   pip3 install --break-system-packages -r requirements.txt
   ```

3. **Build & Run**:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(nproc)
   ./build/ecdat_app
   ```

#### Fedora (39 / 40 / Rawhide):
```bash
sudo dnf install -y gcc-c++ cmake qt6-qtbase-devel qt6-qtcharts-devel qt6-qtsvg-devel python3-devel python3-pip
pip3 install -r requirements.txt
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/ecdat_app
```

---

### 🪟 Windows (MSVC / MinGW)

1. **Install Build Tools**:
   - Install **Visual Studio 2022** (with "Desktop development with C++" workload).
   - Install **CMake** (3.20+): `winget install Kitware.CMake`
   - Install **Python 3.11+**: `winget install Python.Python.3.11`
   - Install **Qt 6**: Install Qt 6.6+ for MSVC 2022 via the [Qt Online Installer](https://www.qt.io/download).

2. **Install Python Dependencies**:
   ```cmd
   python -m pip install -r requirements.txt
   ```

3. **Build via Developer Command Prompt**:
   ```cmd
   cmake -B build -DCMAKE_PREFIX_PATH="C:\Qt\6.6.2\msvc2019_64" -DCMAKE_BUILD_TYPE=Release
   cmake --build build --config Release --parallel
   ```

4. **Launch**:
   ```cmd
   build\Release\ecdat_app.exe
   ```

---

## 🚀 How to Run & Audit

1. **Launch ECDAT**: Run `ecdat_app`.
2. **Select Target**:
   - Click **`Browse Folder...`** or **`Browse File...`** in the top-left sidebar.
   - Example 1 (Source Code): Select `AST-Parser-main 2/test_samples`
   - Example 2 (Encrypted Blobs): Select `AST-Parser-main 2/dataset/encrypted_samples`
3. **Configure Options**:
   - Check `Scan Source Code` (Stage 1 AST).
   - Check `Scan Binary & Ciphertext` (Stage 2 YARA & Stage 3 ML).
   - Adjust Mosca parameters:
     - **Data Shelf-life ($X$)**: Number of years data must remain confidential (Default: 10 years).
     - **Migration Time ($Y$)**: Number of years required to deploy PQC across enterprise (Default: 5 years).
     - **Quantum Arrival ($Z$)**: Projected years until cryptanalytically relevant quantum computers (CRQC).
4. **Click `Start Discovery Audit`**:
   - Watch the obsidian console stream real-time discovery events.
   - The 270° Speedometer Risk Gauge computes the aggregated quantum risk score.
5. **Inspect & Triage**:
   - Click any item in the **CBOM Inventory Table** to view its Deep Inspector card.
   - Right-click on any file in the table to **Open with VS Code, Cursor, Xcode, Zed, or IntelliJ**.
6. **Review History**:
   - Switch to the **`Scan History`** tab to view, search, or reload past audit snapshots.

---

## 📊 CBOM & Report Exports

In the top header toolbar, click:
- **`CycloneDX JSON`**: Generates a standard `cyclonedx_cbom.json` file conforming to CycloneDX v1.5 specification with complete `cryptoProperties` (asset type, key length, quantum risk level, algorithm oid, and NIST PQC migration fix).
- **`Markdown Report`**: Exports an executive `crypto_audit_report.md` formatted with risk summary cards, Mosca status alerts, and remediation plans.
- **`CSV Spreadsheet`**: Generates `cbom_inventory.csv` for enterprise compliance and spreadsheet auditing.

---

## 🔧 Troubleshooting & FAQ

#### Q1: "Stage 3 ML Bridge returns 0 findings on raw `.bin` files"
- **Solution**: Ensure Python ML packages are installed:
  ```bash
  pip3 install joblib scikit-learn numpy pandas scipy
  ```
  ECDAT automatically checks `/Users/prasenjit/miniconda3/bin/python3`, standard `python3`, and virtual environments.

#### Q2: "Qt6 not found during CMake configuration"
- **Solution**: Explicitly set the `CMAKE_PREFIX_PATH` to your Qt6 installation:
  ```bash
  # macOS Homebrew
  cmake -B build -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/qt6"
  
  # Linux
  cmake -B build -DCMAKE_PREFIX_PATH="/usr/lib/x86_64-linux-gnu/cmake/Qt6"
  
  # Windows
  cmake -B build -DCMAKE_PREFIX_PATH="C:/Qt/6.7.0/msvc2019_64"
  ```

#### Q3: "Permission denied running ./build.sh"
- **Solution**: Grant execution permissions:
  ```bash
  chmod +x build.sh
  ./build.sh
  ```

---

## 👥 Contributors & Acknowledgements
- **Development Team**: Advanced Agentic Cryptographic Engineering Group
- **Research Reference**: NIST SP 800-22 Cryptographic Randomness Test Suite
- **Standards**: CycloneDX v1.5 Cryptographic Bill of Materials (CBOM) Standard
