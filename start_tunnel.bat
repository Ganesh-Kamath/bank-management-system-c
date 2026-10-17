@echo off
title SecureBank Public Tunnel
echo ========================================================
echo   Launching Public Tunnel on Port 8080
echo ========================================================
echo.
npx --yes localtunnel --port 8080 --subdomain wicked-candies-knock
pause
