@echo off
echo Компиляция приложения с иконкой...

c:\Windows\Microsoft.NET\Framework\v3.5\csc.exe /win32icon:app.ico /out:1C_Launcher_v0.94.exe Program.cs

if %errorlevel% equ 0 (
    echo.
    echo [OK] Приложение успешно скомпилировано: CredentialApp.exe
) else (
    echo.
    echo [X] Ошибка компиляции!
)

pause