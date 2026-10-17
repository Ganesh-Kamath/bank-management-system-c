@echo off
title College Bank Management System (Simple Version)
echo ========================================================
echo   College Bank Management System (Beginner C Version)
echo ========================================================
echo.

if not exist bank.exe (
    echo Compiling bank.c with GCC...
    gcc -Wall -Wextra -o bank.exe bank.c -lm -lws2_32
    if %errorlevel% neq 0 (
        echo Compilation failed! Please ensure GCC is installed and on your PATH.
        pause
        exit /b
    )
    echo Compilation successful!
    echo.
)

echo Starting bank server on http://127.0.0.1:8081...
start http://127.0.0.1:8081
bank.exe 8081
pause
