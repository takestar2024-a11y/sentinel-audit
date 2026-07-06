@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   SENTINEL AUDIT  診断サーバーを起動します
echo   ブラウザで  http://127.0.0.1:8787/  を開いてください
echo   停止するには この画面で Ctrl + C
echo ============================================
python server.py
pause
