@echo off
cd /d %~dp0

echo ============================================
echo  OneKey University Portal - LAN / Network
echo ============================================

REM ── Find local IP ──────────────────────────────────────────
echo.
echo Your local IP addresses:
ipconfig | findstr /i "IPv4"
echo.

REM ── Ask for IP ─────────────────────────────────────────────
set /p LOCAL_IP=Enter your IPv4 address (e.g. 192.168.1.50): 

REM ── Generate cert with mkcert if not already done ──────────
if not exist "%LOCAL_IP%.pem" (
    echo.
    echo Generating certificate for %LOCAL_IP% with mkcert...
    mkcert %LOCAL_IP%
    if errorlevel 1 (
        echo.
        echo ERROR: mkcert not found or failed.
        echo Install mkcert from: https://github.com/FiloSottile/mkcert/releases
        echo Then run this script again.
        pause
        exit /b 1
    )
)

REM ── Set cert env vars ──────────────────────────────────────
set CERT_FILE=%LOCAL_IP%.pem
set KEY_FILE=%LOCAL_IP%-key.pem
set HOST=0.0.0.0

REM ── Google OAuth (optional) ────────────────────────────────
set GOOGLE_CLIENT_ID=703581643074-sot2treb62qmpfqfo4hk89e0gssh328t.apps.googleusercontent.com
if "%GOOGLE_CLIENT_SECRET%"=="" (
    echo.
    echo Paste your Google Client Secret and press Enter (or press Enter to skip):
    set /p GOOGLE_CLIENT_SECRET=
)

REM ── Install dependencies ───────────────────────────────────
echo.
echo Installing dependencies...
py -3.12 -m pip install -r requirements.txt

REM ── Launch ─────────────────────────────────────────────────
echo.
echo ============================================
echo  Open on THIS machine:   https://127.0.0.1:5000
echo  Open on OTHER devices:  https://%LOCAL_IP%:5000
echo  SAML Viewer:            https://%LOCAL_IP%:5000/saml/viewer
echo ============================================
echo.
py -3.12 app.py
pause
