@echo off
rem Wazuh active-response wrapper: passes the JSON message on stdin to agentic-isolate.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0agentic-isolate.ps1"
exit /b %ERRORLEVEL%
