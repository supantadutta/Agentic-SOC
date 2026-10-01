@echo off
rem Wazuh active-response wrapper: passes the JSON message on stdin to agentic-disable-user.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0agentic-disable-user.ps1"
exit /b %ERRORLEVEL%
