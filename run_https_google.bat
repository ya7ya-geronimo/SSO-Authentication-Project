@echo off
cd /d %~dp0
set GOOGLE_CLIENT_ID=703581643074-sot2treb62qmpfqfo4hk89e0gssh328t.apps.googleusercontent.com
if "%GOOGLE_CLIENT_SECRET%"=="" (
  echo Paste your NEW Google Client Secret then press Enter:
  set /p GOOGLE_CLIENT_SECRET=
)
py -3.12 -m pip install -r requirements.txt
py -3.12 app.py
pause
