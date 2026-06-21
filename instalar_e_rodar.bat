@echo off
setlocal enableextensions
title CamScan - Instalador

:: ============================================================
:: Truque: se foi chamado por duplo-clique, relanca com cmd /k
:: para a janela NUNCA fechar sozinha (sempre veremos o erro).
:: ============================================================
if not defined CAMSCAN_RELAUNCHED (
    set "CAMSCAN_RELAUNCHED=1"
    start "" cmd /k "%~f0"
    exit /b
)

:: ============================================================
:: Auto-eleva para Administrador se necessario
:: ============================================================
net session >nul 2>&1
if errorlevel 1 (
    echo Solicitando privilegios de Administrador...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/k','\"%~f0\"' -Verb RunAs"
    exit /b
)

:: ============================================================
:: Vai para a pasta do script (pushd suporta UNC)
:: ============================================================
pushd "%~dp0" || (
    echo ERRO: nao consegui acessar a pasta: %~dp0
    goto :FIM
)

echo =============================================
echo        BEM-VINDO AO CAMSCAN
echo =============================================
echo.

:: ============================================================
:: [1/5] Python
:: ============================================================
echo [1/5] Verificando Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python nao encontrado. Baixando...
    curl -L -o python_installer.exe https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe
    if errorlevel 1 (
        echo ERRO ao baixar o Python.
        goto :FIM
    )
    echo Instalando Python ^(aguarde alguns minutos^)...
    start /wait "" python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1
    del python_installer.exe >nul 2>&1
    set "PATH=%PATH%;C:\Program Files\Python313;C:\Program Files\Python313\Scripts"
    echo Python instalado!
) else (
    echo Python ja instalado!
)

:: ============================================================
:: [2/5] Nmap
:: ============================================================
echo.
echo [2/5] Verificando Nmap...
nmap --version >nul 2>&1
if errorlevel 1 (
    echo Nmap nao encontrado. Baixando...
    curl -L -o nmap_installer.exe https://nmap.org/dist/nmap-7.95-setup.exe
    if errorlevel 1 (
        echo ERRO ao baixar o Nmap.
        goto :FIM
    )
    echo Instalando Nmap ^(aguarde alguns minutos^)...
    start /wait "" nmap_installer.exe /S
    del nmap_installer.exe >nul 2>&1
    set "PATH=%PATH%;C:\Program Files (x86)\Nmap;C:\Program Files\Nmap"
    echo Nmap instalado!
) else (
    echo Nmap ja instalado!
)

:: ============================================================
:: [3/5] Bibliotecas Python
:: ============================================================
echo.
echo [3/5] Preparando ambiente virtual e instalando bibliotecas Python...
if not exist .venv (
    python -m venv .venv
    if errorlevel 1 (
        echo ERRO ao criar ambiente virtual.
        goto :FIM
    )
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERRO ao instalar bibliotecas Python.
    goto :FIM
)
echo Bibliotecas instaladas!

if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo Arquivo .env criado a partir de .env.example.
    )
)

:: ============================================================
:: [4/5] Nuclei
:: ============================================================
echo.
echo [4/5] Verificando Nuclei...
if not exist nuclei.exe (
    echo ATENCAO: nuclei.exe nao encontrado nesta pasta.
    echo Coloque o nuclei.exe junto com este arquivo .bat.
    goto :FIM
)
echo Nuclei encontrado!

:: ============================================================
:: [5/5] Inicia o CamScan
:: ============================================================
echo.
echo [5/5] Iniciando CamScan...
echo =============================================
echo   CamScan sera aberto no seu navegador.
echo   Para fechar, pressione CTRL+C nesta janela.
echo =============================================
echo.
python -m streamlit run interface_streamlit.py

:FIM
popd >nul 2>&1
echo.
echo =============================================
echo   Fim da execucao. Pressione qualquer tecla.
echo =============================================
pause >nul
endlocal
