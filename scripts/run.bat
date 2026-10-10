@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process; .\port-check.ps1"
pause
