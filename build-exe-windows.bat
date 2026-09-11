@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m pip install --upgrade pyinstaller
    py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name VB6RobotAnalyzer --paths src main.py
) else (
    python -m pip install --upgrade pyinstaller
    python -m PyInstaller --noconfirm --clean --onefile --windowed --name VB6RobotAnalyzer --paths src main.py
)
if errorlevel 1 (
    echo Falha ao gerar o executavel.
) else (
    echo Executavel criado em dist\VB6RobotAnalyzer.exe
)
pause
