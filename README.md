# 🛡️ ECDAT — Enterprise Cryptographic Discovery & Assessment Tool

[![Live Code](https://img.shields.io/badge/🔗_Source_Code-bit.ly%2Fecdat--code-blue.svg?style=for-the-badge)](https://bit.ly/ecdat-code)
[![Demo Video](https://img.shields.io/badge/▶️_Product_Demo-bit.ly%2Fecdat--demo-red.svg?style=for-the-badge)](https://bit.ly/ecdat-demo)
[![Solution Video](https://img.shields.io/badge/🎬_Architecture_Video-bit.ly%2Fecdat--explain-purple.svg?style=for-the-badge)](https://bit.ly/ecdat-explain)

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-23-00599C.svg?logo=c%2B%2B)](https://en.cppreference.com/)
[![Qt Version](https://img.shields.io/badge/Qt-6.5%2B-41CD52.svg?logo=qt)](https://www.qt.io/)
[![CBOM Standard](https://img.shields.io/badge/CBOM-CycloneDX%20v1.5-8B5CF6.svg)](https://cyclonedx.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-F59E0B.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/)

**ECDAT** is a high-performance, cross-platform enterprise cryptographic auditor, post-quantum risk analyzer, and **Cryptographic Bill of Materials (CBOM)** generation platform. It automatically inspects enterprise codebases, binary firmware, X.509 certificates, and unlabelled ciphertexts to discover classical cryptographic vulnerabilities, compute quantum migration timelines via **Mosca's Theorem**, and generate compliant **CycloneDX v1.5 CBOMs**.

---

## ⚡ Quick Links & Video Demos

| Resource | Short Link | Description |
| :--- | :--- | :--- |
| 💻 **Prototype & Source Code** | [`bit.ly/ecdat-code`](https://bit.ly/ecdat-code) | Official GitHub repository, branches, and releases |
| ▶️ **Product Demo Video** | [`bit.ly/ecdat-demo`](https://bit.ly/ecdat-demo) | Live interactive walkthrough of the Qt6 GUI, CBOM & exports |
| 🎬 **Solution & Architecture** | [`bit.ly/ecdat-explain`](https://bit.ly/ecdat-explain) | 40-second technical explainer on the 3-tier discovery pipeline |

---

## 🚀 Instant Run: Pre-Built Portable Windows App (Zero Setup)

You do **not** need to install Qt6, CMake, or Python to test ECDAT on Windows.

1. Download the latest standalone **`ECDAT-Windows-x64.zip`** from [GitHub Releases](https://github.com/prasenjitmohanta/ECDAT-V1/releases) or the [Actions Artifacts](https://github.com/prasenjitmohanta/ECDAT-V1/actions).
2. **Extract** the ZIP folder on your computer.
3. Double-click **`ecdat_app.exe`**.

> **Note**: The portable release package includes pre-bundled embedded Python and calibrated Random Forest model weights (`ecdat_rf_model_36mb.pkl`). It runs **100% offline** with zero environment configuration!

---

## 🌿 Repository Branches Guide

* **`fix-windows-gui-portable-python` (Recommended for Windows)**:
  * Contains all Windows MSVC header initialization fixes, path space quoting for subprocesses, and automated embedded Python packaging.
  * **Use this branch for building or running on Windows.**
* **`main`**:
  * Core development branch (macOS / Linux optimized).

To switch to the Windows-ready branch:
```bash
git checkout fix-windows-gui-portable-python
```

---

## 🌟 Key Capabilities & Innovations

1. **Stage 1: AST Semantic Code Parser (Tree-Sitter)**:
   * Native C++ structural AST analysis for C/C++ and Python.
   * **Dynamic Parameter Extraction**: Evaluates AST `call_expression` nodes to extract key bit lengths (`AES-128`, `AES-256`, `RSA-2048`, `RSA-4096`) and elliptic curve parameters (`NIST P-256`, `NIST P-384`, `Curve25519`).
   * **Zero False Positives**: Uses two-pass semantic symbol tracking to verify active function invocation vs. unused/dead imports.

2. **Stage 2: YARA Signature Engine**:
   * Scans compiled binaries, shared libraries, and firmware (`.exe`, `.dll`, `.so`, `.elf`).
   * Matches raw cryptographic byte constants: AES S-Boxes, SHA-256 round constants, and OpenSSL symbol strings.

3. **Stage 3: NIST SP 800-22 ML Ciphertext Triage (Our USP)**:
   * Solves the blind spot of **unlabelled binary blobs** with no headers or symbol tables.
   * Powered by a dataset pipeline (`sid0nair` architecture): generates multi-cipher encrypted datasets, runs the official **NIST SP 800-22 Statistical Test Suite**, and extracts 20+ randomness features (Monobit frequency $p$-values, Shannon entropy, block repetition ratios, multi-lag autocorrelations).
   * Calibrated **Random Forest Classifier** predicts cipher families (`AES`, `3DES`, `Blowfish`, `CAST`, `RC4`, `ChaCha20`) with statistical confidence scores.

4. **X.509 Certificate & Protocol Config Scanner**:
   * Inspects `.pem`, `.crt`, `.key`, `.conf`, `.yaml` files.
   * Identifies hardcoded private keys (PKCS#8 RSA, SEC1 ECC) and deprecated protocol versions (`SSLv3`, `TLS 1.0`, `TLS 1.1`).

5. **Quantum Risk Engine & Mosca's Theorem**:
   * Computes Mosca’s Deficit formula:
     $$\text{Risk Score} = \frac{X + Y}{Z} \quad \text{and Margin} = Z - (X + Y)$$
     * $X$ = Data Secrecy Horizon (years data must remain secure)
     * $Y$ = PQC Migration Time (years needed to replace crypto)
     * $Z$ = Quantum Arrival Time (years until Cryptanalytically Relevant Quantum Computer)
   * Flags **Harvest-Now-Decrypt-Later (HNDL)** active risks and classifies threats under **Shor's Algorithm** (broken asymmetric keys) vs. **Grover's Algorithm** (halved symmetric strength).

6. **Direct NIST Post-Quantum Standards Mapping (August 2024)**:
   * RSA / Diffie-Hellman $\longrightarrow$ **FIPS 203: ML-KEM-768 / 1024 (Kyber)**
   * ECC / ECDSA $\longrightarrow$ **FIPS 204: ML-DSA-65 (Dilithium) / FIPS 205: SLH-DSA**
   * Legacy Symmetric (DES, 3DES, RC4) $\longrightarrow$ **AES-256-GCM / ChaCha20-Poly1305**

7. **Multi-Format Enterprise Exports**:
   * **CycloneDX v1.5 CBOM JSON**: Official software supply chain standard with `cryptoProperties`.
   * **CSV Spreadsheet**: Full asset inventory for enterprise spreadsheets.
   * **Markdown Audit Report**: Executive-ready audit summary with remediation notes.

---

## 🏗️ Multi-Stage Architecture

```
                                  ┌────────────────────────┐
                                  │   Target Audit Path    │
                                  └───────────┬────────────┘
                                              │
         ┌────────────────────────────────────┼────────────────────────────────────┐
         ▼                                    ▼                                    ▼
[ Source Code Files ]               [ Executables & Binaries ]           [ Unlabelled Raw Blobs ]
(.c, .cpp, .h, .py)                 (.exe, .dll, .so, .elf)              (.bin, .dat, .raw)
         │                                    │                                    │
         ▼                                    ▼                                    ▼
┌─────────────────────────┐          ┌─────────────────────────┐          ┌─────────────────────────┐
│  Stage 1: Tree-Sitter   │          │  Stage 2: YARA Engine   │          │ Stage 3: Random Forest  │
│   Semantic AST Parser   │          │   S-Boxes & Constants   │          │  NIST SP 800-22 Triage  │
└────────────┬────────────┘          └────────────┬────────────┘          └────────────┬────────────┘
             │                                    │                                    │
             └────────────────────────────────────┼────────────────────────────────────┘
                                                  │
                                                  ▼
                                    ┌───────────────────────────┐
                                    │    Mosca Risk Engine      │
                                    │   Score = (X + Y) / Z     │
                                    └─────────────┬─────────────┘
                                                  │
                                                  ▼
                                    ┌───────────────────────────┐
                                    │  FIPS 203/204/205 Mapping │
                                    └─────────────┬─────────────┘
                                                  │
                                                  ▼
                          ┌───────────────────────────────────────────────┐
                          │             ECDAT Graphical Hub               │
                          │  • High-Contrast Radar    • CBOM Inventory    │
                          │  • Asset Inspector        • Terminal Console  │
                          │  • CycloneDX JSON Export  • Scan History      │
                          └───────────────────────────────────────────────┘
```

---

## 💻 Local Compilation & Build Instructions

### 📋 Prerequisites
* **C++ Compiler**: C++23 compliant (`MSVC 2022`, `g++ 13+`, or `clang++ 16+`)
* **CMake**: 3.20 or newer
* **Qt 6**: Qt 6.5+ (Widgets, Core, Charts, Svg, Concurrent)
* **Python**: 3.11+ (with `joblib`, `scikit-learn`, `numpy`, `pandas`)

---

### 🪟 Windows (MSVC 2022)

1. **Clone the Windows-Ready Branch**:
   ```cmd
   git clone -b fix-windows-gui-portable-python https://github.com/prasenjitmohanta/ECDAT-V1.git
   cd ECDAT-V1
   ```

2. **Install Python ML Dependencies**:
   ```cmd
   pip install joblib scikit-learn numpy pandas
   ```

3. **Configure and Build with CMake**:
   ```cmd
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build --config Release --parallel
   ```

4. **Run**:
   ```cmd
   build\Release\ecdat_app.exe
   ```

---

### 🍎 macOS (Apple Silicon & Intel)

1. **Install Prerequisites via Homebrew**:
   ```bash
   brew update
   brew install cmake qt@6 python@3.11
   pip3 install joblib scikit-learn numpy pandas
   ```

2. **Configure and Build**:
   ```bash
   export CMAKE_PREFIX_PATH="/opt/homebrew/opt/qt6:$CMAKE_PREFIX_PATH"
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(sysctl -n hw.ncpu)
   ```

3. **Launch**:
   ```bash
   ./build/ecdat_app.app/Contents/MacOS/ecdat_app
   ```

---

### 🐧 Linux (Ubuntu 22.04 / 24.04 LTS)

1. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y build-essential cmake qt6-base-dev qt6-charts-dev qt6-svg-dev \
                       libqt6concurrent6 python3 python3-pip python3-dev
   pip3 install --break-system-packages joblib scikit-learn numpy pandas
   ```

2. **Build and Run**:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(nproc)
   ./build/ecdat_app
   ```

---

## 🚀 How to Run an Audit

1. **Launch ECDAT** (`ecdat_app.exe` or `./ecdat_app`).
2. **Select Target**: Click **`Browse Folder...`** or **`Browse File...`**.
3. **Select Scanners**: Ensure `Scan Source Code`, `Scan Binary & Ciphertext`, and `Scan Certificates & Configs` are checked.
4. **Click `▶ Run Full Audit`**.
5. **Inspect CBOM**: Switch to the **CBOM Inventory** tab to inspect discovered algorithms, key lengths, CWE IDs, and Mosca risk urgency.
6. **Export**: Click **`Export CBOM / CSV...`** at the top-right to export official **CycloneDX v1.5 CBOM JSON**, CSV, or Markdown reports.

---

## 👥 Team & Acknowledgements
* **Project**: ECDAT — Smart India Hackathon 2026
* **ML Architecture & Dataset Engine**: NIST SP 800-22 Feature Pipeline by `sid0nair`
* **Standards**: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), CycloneDX v1.5
