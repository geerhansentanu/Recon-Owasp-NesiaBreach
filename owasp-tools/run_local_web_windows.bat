@echo off
setlocal

echo OWASP Rekon Aman Lokal - NesiaBreach
echo.

if not exist ".venv\Scripts\python.exe" (
  echo Membuat virtual environment...
  py -m venv .venv
  if errorlevel 1 (
    echo Gagal membuat venv. Install Python 3.11+ dan centang "Add Python to PATH".
    pause
    exit /b 1
  )
)

echo Install/update dependency...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo Gagal install dependency.
  pause
  exit /b 1
)

echo.
echo Membuka browser lokal...
".venv\Scripts\python.exe" local_web.py
pause
