@echo off
setlocal

echo OWASP Rekon Aman
echo.

if "%~1"=="" (
  set /p TARGET=Masukkan target domain/URL: 
) else (
  set TARGET=%~1
)

if "%TARGET%"=="" (
  echo Target kosong.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Membuat virtual environment...
  py -m venv .venv
  if errorlevel 1 (
    echo Gagal membuat venv. Pastikan Python sudah terinstall dan perintah py tersedia.
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
echo Menjalankan rekon aman untuk %TARGET%
".venv\Scripts\python.exe" owasp_recon.py "%TARGET%" --scope-file scope.txt --out report.html --json-out report.json
if errorlevel 1 (
  echo Scan selesai dengan peringatan/error. Cek output di atas.
)

echo.
echo Membuka report.html...
start "" "report.html"
pause
