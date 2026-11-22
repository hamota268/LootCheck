@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo        LootCheck - Windows Build Script
echo        "Check your loot before you run it."
echo ========================================================
echo.

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

:: Check Python availability
set PYTHON_CMD=python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
        set "PYTHON_CMD=%LOCALAPPDATA%\Python\bin\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    ) else (
        echo [ERROR] Python not found on PATH or standard locations.
        echo Please ensure Python 3.10+ is installed.
        pause
        exit /b 1
    )
)

echo [1/5] Checking virtual environment...
if not exist ".venv" (
    echo Creating virtual environment with %PYTHON_CMD%...
    "%PYTHON_CMD%" -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

set "VENV_PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"
set "VENV_PIP=%SCRIPT_DIR%.venv\Scripts\pip.exe"

echo.
echo [2/5] Installing dependencies...
"%VENV_PYTHON%" -m pip install --upgrade pip
"%VENV_PYTHON%" -m pip install -r requirements.txt pillow
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo [3/5] Running automated tests...
"%VENV_PYTHON%" -m pytest tests/ -v
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Tests failed! Aborting build to ensure quality.
    pause
    exit /b 1
)
echo All tests passed successfully!

echo.
echo [4/5] Building standalone executable with PyInstaller...

:: Generate icon if not present
if not exist "assets\icon.ico" (
    echo Generating application icon...
    "%VENV_PYTHON%" generate_icon.py
)

:: Find tkinterdnd2 package location safely via temporary file to avoid CMD quoting issues
"%VENV_PYTHON%" -c "import tkinterdnd2, os; print(os.path.dirname(tkinterdnd2.__file__))" > "%TEMP%\lootcheck_tkdnd.txt" 2>nul
set /p TKDND_DIR=<"%TEMP%\lootcheck_tkdnd.txt"
del "%TEMP%\lootcheck_tkdnd.txt" 2>nul

echo Bundling with tkinterdnd2 from: !TKDND_DIR!

if defined TKDND_DIR (
    "%VENV_PYTHON%" -m PyInstaller ^
        --noconfirm ^
        --clean ^
        --windowed ^
        --onefile ^
        --name LootCheck ^
        --icon "assets\icon.ico" ^
        --add-data "assets;assets" ^
        --add-data "!TKDND_DIR!;tkinterdnd2" ^
        --hidden-import "tkinterdnd2" ^
        --hidden-import "keyring" ^
        --hidden-import "keyring.backends.Windows" ^
        --hidden-import "requests" ^
        main.py
) else (
    "%VENV_PYTHON%" -m PyInstaller ^
        --noconfirm ^
        --clean ^
        --windowed ^
        --onefile ^
        --name LootCheck ^
        --icon "assets\icon.ico" ^
        --add-data "assets;assets" ^
        --hidden-import "tkinterdnd2" ^
        --hidden-import "keyring" ^
        --hidden-import "keyring.backends.Windows" ^
        --hidden-import "requests" ^
        main.py
)

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] PyInstaller build failed!
    pause
    exit /b 1
)

echo.
echo [5/5] Build verification...
if exist "dist\LootCheck.exe" (
    echo ========================================================
    echo  SUCCESS! Standalone executable generated at:
    echo  %SCRIPT_DIR%dist\LootCheck.exe
    echo ========================================================
    dir "dist\LootCheck.exe" | findstr LootCheck.exe
) else (
    echo [ERROR] Output binary dist\LootCheck.exe was not found.
    pause
    exit /b 1
)

echo.
echo Build complete.
pause
