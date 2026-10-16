@echo off
cd /d "%~dp0"
start "ShieldCode Server" /D "%~dp0" py server.py
timeout /t 2 /nobreak > nul
start "" http://127.0.0.1:8765
