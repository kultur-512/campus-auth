@echo off
chcp 65001 >nul
echo 正在编译校园网自动认证…
cd /d "%~dp0"
dotnet publish src\CampusAuth.csproj -c Release -o dist
if errorlevel 1 (
    echo.
    echo 编译失败，请确认已安装 .NET 9 SDK：https://dot.net
    pause
    exit /b 1
)
echo.
echo 完成：dist\CampusAuth.exe
pause
