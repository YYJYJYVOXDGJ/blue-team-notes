@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
echo ============================================
echo    blue-team-notes-mcp  selfcheck
echo    read-only check, changes nothing
echo ============================================
echo.

set PY=
where python >nul 2>nul
if %errorlevel%==0 set PY=python
if "%PY%"=="" (
  where py >nul 2>nul
  if %errorlevel%==0 set PY=py
)
if "%PY%"=="" if exist "F:\PY\python.exe" set PY="F:\PY\python.exe"
if "%PY%"=="" if exist "C:\Users\13874\.workbuddy\binaries\python\versions\3.13.12\python.exe" set PY="C:\Users\13874\.workbuddy\binaries\python\versions\3.13.12\python.exe"

if "%PY%"=="" (
  echo [ERROR] python not found
  pause
  exit /b 1
)

%PY% selfcheck.py

echo.
echo ============================================
echo    done.
echo ============================================
pause
