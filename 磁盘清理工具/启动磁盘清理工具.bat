@echo off
chcp 65001 >nul
title 智能磁盘清理工具
echo ==================================
echo   智能磁盘清理工具 SmartDiskCleaner
echo   正在启动...
echo ==================================
echo.
python "%~dp0disk_cleaner.py"
if %errorlevel% neq 0 (
    echo.
    echo [错误] 运行失败，请确保已安装 Python 3.x
    echo 下载地址: https://www.python.org/downloads/
    echo.
    pause
)