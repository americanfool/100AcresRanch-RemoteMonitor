@echo off
echo Installing dependencies...
pip install ping3 matplotlib paramiko pystray Pillow==11.2.1 >nul 2>&1

echo.
echo Starting Heartbeat Monitor...
start "" /min pythonw.exe heartbeat_monitor.py 