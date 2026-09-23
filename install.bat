@echo off
echo ============================================
echo      Installation des dependances TraceVault
echo ============================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo Telechargez-le sur https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [*] Mise a jour de pip...
python -m pip install --upgrade pip

echo.
echo [*] Installation des dependances...
echo.

pip install requests
pip install colorama
pip install pystyle
pip install phonenumbers
pip install httpx
pip install trio
pip install holehe
pip install Pillow
pip install pillow-heif

echo.
echo ============================================
echo  Installation terminee ! Lancez le programme
echo  avec : python CLIversion.py
echo ============================================
pause
