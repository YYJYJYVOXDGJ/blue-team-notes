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
rem 以下使用环境变量展开，避免把本机用户名硬编码进仓库
if "%PY%"=="" if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if "%PY%"=="" if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if "%PY%"=="" if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

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
