@echo off
chcp 65001 >nul
title C盘安全缓存清理工具
echo ==================================
echo   C盘安全缓存清理工具
echo   只处理白名单缓存文件，不删除目录
echo ==================================
echo.
python "%~dp0磁盘清理工具_安全版.py"
if %errorlevel% neq 0 (
    echo.
    echo [错误] 未找到可用的 Python 3，请先安装 Python 3。
    echo.
    pause
)
