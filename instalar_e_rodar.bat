@echo off
title CamScan - Instalador
echo =============================================
echo        BEM-VINDO AO CAMSCAN
echo =============================================
echo.

:: Verifica se Python esta instalado
echo [1/5] Verificando Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python nao encontrado. Baixando...
    curl -o python_installer.exe https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe
    python_installer.exe /quiet InstallAllUsers=1 PrependPath=1
    del python_installer.exe
    echo Python instalado com sucesso!
) else (
    echo Python ja instalado!
)

:: Verifica se Nmap esta instalado
echo.
echo [2/5] Verificando Nmap...
nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Nmap nao encontrado. Baixando...
    curl -o nmap_installer.exe https://nmap.org/dist/nmap-7.95-setup.exe
    nmap_installer.exe /S
    del nmap_installer.exe
    echo Nmap instalado com sucesso!
) else (
    echo Nmap ja instalado!
)

:: Instala bibliotecas Python
echo.
echo [3/5] Instalando bibliotecas Python...
pip install python-nmap streamlit groq python-dotenv
echo Bibliotecas instaladas!

:: Verifica se nuclei.exe existe na pasta
echo.
echo [4/5] Verificando Nuclei...
if not exist nuclei.exe (
    echo ATENCAO: nuclei.exe nao encontrado na pasta.
    echo Certifique-se de que o nuclei.exe esta na mesma pasta que este arquivo.
    pause
    exit
) else (
    echo Nuclei encontrado!
)

:: Inicia o CamScan
echo.
echo [5/5] Iniciando CamScan...
echo =============================================
echo   CamScan sera aberto no seu navegador.
echo   Para fechar, pressione CTRL+C nesta janela.
echo =============================================
echo.
python -m streamlit run interface_streamlit.py

pause