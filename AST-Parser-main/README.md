# ECDAT - Multi-Language AST Cryptographic Discovery Parser

High-performance C++20 static analysis parser for discovering cryptographic algorithms, key lengths, and cipher modes across heterogeneous codebases (C/C++, Python). Built as Stage 1 of the **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)** for SIH 2026 (Problem ID: SIH26164).

## ?? Features
- **Tree-Sitter Multi-Language AST Traversal**: Deterministic parsing of C/C++ (OpenSSL, Native APIs) and Python (PyCryptodome, hashlib, rsa).
- **Exact Key & Mode Extraction**: Identifies key sizes (128-bit, 256-bit, 2048-bit) and cipher modes (GCM, CBC, ECB).
- **Post-Quantum Risk Categorization**: Automatically evaluates risk profiles against Shor's and Grover's quantum algorithms.
- **Fast Offline Execution**: Written in modern C++20 using `cpp-tree-sitter`.

## ??? Build & Run

```bash
# 1. Configure
cmake -B build

# 2. Compile
cmake --build build --config Release

# 3. Scan Target Repository
./build/ecdat_ast_cli ./test_samples
```

