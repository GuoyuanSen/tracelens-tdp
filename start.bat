@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
  if errorlevel 1 goto need_python
  echo Open http://127.0.0.1:8765 in your browser after startup.
  py -3 run.py
  goto done
)
where python >nul 2>nul
if %errorlevel% neq 0 goto need_python
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if errorlevel 1 goto need_python
echo Open http://127.0.0.1:8765 in your browser after startup.
python run.py
goto done
:need_python
echo Python 3.9+ is required. Install it from https://www.python.org/downloads/
:done
pause
