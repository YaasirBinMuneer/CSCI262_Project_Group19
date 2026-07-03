@echo off
echo =======================================
echo   CSCI_262_project_GROUP19 - Password Similarity Checker
echo =======================================
echo.
python -c "import flask" 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    echo.
)
echo Starting web server...
echo Open http://localhost:5000 in your browser.
echo Press Ctrl+C to stop.
echo.
python app.py
pause
