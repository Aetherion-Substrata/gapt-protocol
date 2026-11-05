@echo off
REM GAPT 0.12.0 - one-shot push of this folder to the empty public repo FizzNetwork/gapt-protocol.
REM Run from this folder on the rig (uses your own git credentials). Safe to re-run.
cd /d "%~dp0"
if not exist .git git init -b main
git add -A
git -c user.name="FizzNetwork" -c user.email="oneupmediagroup@gmail.com" commit -m "GAPT Protocol 0.12.0 - bridgeclass typed edges, noncommercial licence" || echo (nothing new to commit)
git remote remove origin 2>nul
git remote add origin https://github.com/FizzNetwork/gapt-protocol.git
git push -u origin main
echo.
echo Pushed. Next: npm publish   (from this folder; name gapt-protocol, version 0.12.0)
