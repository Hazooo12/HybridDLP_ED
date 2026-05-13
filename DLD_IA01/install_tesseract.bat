@echo off
REM Install Tesseract-OCR for Windows
REM Script to download and install latest Tesseract release

echo Downloading Tesseract-OCR installer...
cd %TEMP%

REM Using curl to download (Windows 10+)
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/UB-Mannheim/tesseract/releases/download/v5.3.1/tesseract-ocr-w64-setup-v5.3.1.20230628.exe' -OutFile 'tesseract-installer.exe' -UserAgent 'Mozilla/5.0'"

if errorlevel 1 (
    echo Failed to download installer. Please visit:
    echo https://github.com/UB-Mannheim/tesseract/releases
    echo Download: tesseract-ocr-w64-setup-v5.3.1.exe
    pause
    exit /b 1
)

echo Running installer...
echo.
echo IMPORTANT: During installation, keep the default path:
echo   C:\Program Files\Tesseract-OCR
echo.
pause
tesseract-installer.exe

echo Installation complete!
echo Checking if Tesseract is in PATH...
where tesseract

pause
