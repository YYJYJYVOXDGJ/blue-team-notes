@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
title blue-team-notes - 现场演示

echo ============================================
echo    blue-team-notes  现场演示
echo    全程离线 / 零依赖 / 只读
echo ============================================
echo.

set PY=
where python >nul 2>nul
if %errorlevel%==0 set PY=python
if "%PY%"=="" (
  where py >nul 2>nul
  if %errorlevel%==0 set PY=py
)
rem 使用环境变量展开，避免把本机路径硬编码进仓库
if "%PY%"=="" if exist "F:\PY\python.exe" set PY="F:\PY\python.exe"
if "%PY%"=="" if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if "%PY%"=="" if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if "%PY%"=="" if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

if "%PY%"=="" (
  echo [ERROR] 未找到 python，请先安装 Python 3.9+ 并加入 PATH
  pause
  exit /b 1
)

%PY% demo.py

echo.
echo ============================================
echo    演示结束
echo ============================================
pause
