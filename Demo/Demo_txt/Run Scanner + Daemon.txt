@echo off
color F0
start "Detector" "C:\Program Files\Ranflood\Detector\kaspersky_and_vt.exe" \K "color F0"
timeout /t 37 
start "Ranflood Daemon" "C:\Program Files\Ranflood\ranfloodd.exe" settings.ini \K "color F0"

