@echo off
rem Wazuh active-response wrapper: passes the JSON message on stdin to agentic-collect-evidence.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0agentic-collect-evidence.ps1"
exit /b %ERRORLEVEL%
