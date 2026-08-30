@echo off
REM ==============================================================================
REM  ECDAT — One-Click Build Script for Windows (MSVC / MinGW)
REM ==============================================================================

setlocal enabledelayedexpansion

echo ======================================================================
echo     ECDAT -- Enterprise Cryptographic Discovery ^& Assessment Tool
echo     Windows Build ^& Compilation System
echo ======================================================================
echo.

REM 1. Check CMake
where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] CMake is not installed or not in PATH!
    echo Please install CMake from https://cmake.org/download/ and add to PATH.
    pause
    exit /b 1
)

REM 2. Check Python ML Dependencies
where python >nul 2>nul
if %errorlevel% equ 0 (
    echo [INFO] Installing required Python ML dependencies...
    python -m pip install -r requirements.txt
) else (
    echo [WARNING] Python not found. ML inference requires Python 3.10+ with scikit-learn.
)

REM 3. Configure Project
if not exist "build" mkdir build

echo [INFO] Configuring CMake Project...
cmake -B build -DCMAKE_BUILD_TYPE=Release

if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed! Ensure Qt6 is installed and accessible.
    pause
    exit /b 1
)

REM 4. Compile Target
echo [INFO] Building ECDAT Targets...
cmake --build build --config Release --parallel

if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo ======================================================================
echo   [SUCCESS] ECDAT has been compiled successfully!
echo ======================================================================
echo.
echo Executable location: build\Release\ecdat_app.exe or build\ecdat_app.exe
echo.
set /p LAUNCH="Would you like to launch ECDAT now? (Y/N): "
if /i "%LAUNCH%"=="Y" (
    if exist "build\Release\ecdat_app.exe" (
        start "" "build\Release\ecdat_app.exe"
    ) else if exist "build\ecdat_app.exe" (
        start "" "build\ecdat_app.exe"
    )
)

endlocal
