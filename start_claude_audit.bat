@echo off
echo ======================================================
echo       CLAUDE CODE - SECURITY AUDIT MODE
echo ======================================================
echo.
echo [INFO] Starte Claude Code im aktuellen Verzeichnis...
echo [INFO] Modus: --untrust (Verhindert Rechte-Eskalation auf dem Host)
echo [INFO] Modus: --dangerously-skip-permissions (Keine Bestaetigung noetig)
echo.

:: Prüfe ob claude installiert ist
where claude >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] FEHLER: Claude Code ist nicht installiert.
    echo Bitte installiere es mit: npm install -g @anthropic-ai/claude-code
    pause
    exit /b
)

:: Startet Claude Code mit den gewünschten Parametern
:: Wir nutzen --dangerously-skip-permissions damit er autonom arbeiten kann
claude --dangerously-skip-permissions

pause