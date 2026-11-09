@echo off
setlocal
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
dumpbin /nologo /exports C:\Windows\System32\dwmapi.dll | python gen_exports.py || exit /b 1
if not exist build mkdir build
cl /nologo /O2 /MT /W4 /EHsc /GS /DUNICODE /D_UNICODE /LD src\hvfix.cpp /Fobuild\ /Febuild\dwmapi.dll ^
   /link /DLL /NOLOGO kernel32.lib user32.lib psapi.lib || exit /b 1
del build\dwmapi.exp build\dwmapi.lib 2>nul
echo.
echo Built: %~dp0build\dwmapi.dll

