@echo off
title SecureBank Management System
echo ========================================================
echo   College Bank Management System (Pure C Engine)
echo ========================================================
echo.

if not exist Bankmanagement.exe (
    echo Compiling Bankmanagement.c with GCC...
    gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement.exe Bankmanagement.c -lm -lws2_32
    if %errorlevel% neq 0 (
        echo Compilation failed! Please ensure GCC is installed and on your PATH.
        pause
        exit /b
    )
    echo Compilation successful!
    echo.
)

echo Starting bank server on http://127.0.0.1:8080...
start http://127.0.0.1:8080
Bankmanagement.exe
pause
