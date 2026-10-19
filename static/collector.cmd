@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $p=Join-Path $env:TEMP ('me-device-collector-' + [guid]::NewGuid().ToString('N') + '.ps1'); try { Invoke-WebRequest -UseBasicParsing -Uri '__COLLECTOR_URL__' -OutFile $p; & $p } catch { Write-Host $_ -ForegroundColor Red; exit 1 } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }"
set "ME_RESULT=%ERRORLEVEL%"
if not "%ME_RESULT%"=="0" echo Pengumpulan data gagal. Periksa koneksi atau hubungi administrator.
echo.
pause
exit /b %ME_RESULT%
