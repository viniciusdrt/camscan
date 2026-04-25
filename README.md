# CamScan

Ferramenta automatizada de diagnóstico de segurança para câmeras IP, voltada para usuários sem conhecimento técnico.

## O problema

Câmeras IP são um dos dispositivos mais vulneráveis em redes domésticas e corporativas. A maioria sai de fábrica com senhas padrão, firmware desatualizado e configurações inseguras — e os donos simplesmente não sabem disso. Um atacante com acesso à rede local pode acessar o feed ao vivo, usar a câmera como porta de entrada para outros dispositivos ou recrutar o equipamento para ataques externos.

## A solução

O CamScan escaneia automaticamente a rede local, identifica câmeras IP conectadas e verifica se há vulnerabilidades conhecidas. Ao final, gera um relatório em linguagem simples explicando o que foi encontrado e o que fazer.

## Como funciona

1. O usuário informa a faixa de rede (ex: `192.168.0.0/24`)
2. O CamScan descobre automaticamente as câmeras conectadas
3. Cada câmera é testada contra vulnerabilidades conhecidas
4. Um relatório é gerado com classificação de severidade e recomendação de ação

## Para quem é

Pequenas empresas, condomínios, clínicas e comércios — qualquer ambiente que usa câmeras IP mas não tem equipe de TI dedicada para monitorar a segurança desses dispositivos.

## Tecnologias utilizadas

- Python
- Nmap + python-nmap
- Nuclei
- Groq API (Llama 3.3 70B)
- Streamlit

## Equipe

Desenvolvido por Vinicius Duarte e Enzo Gomes — estudantes de Ciência da Computação no UniCEUB.

## Como usar

### Usuário final (recomendado)
1. Baixe o arquivo `CamScan.zip` na seção [Releases](https://github.com/viniciusdrt/camscan/releases)
2. Extraia o arquivo
3. Abra o arquivo `.env` e adicione sua chave do Groq:
GROQ_API_KEY=sua_chave_aqui
4. Clique duas vezes em `instalar_e_rodar.bat`
5. O CamScan abrirá automaticamente no navegador

### Desenvolvedores
1. Clone o repositório:
```bash
   git clone https://github.com/viniciusdrt/camscan.git
```
2. Adicione o `nuclei.exe` na raiz do projeto
3. Crie o arquivo `.env` com sua chave do Groq
4. Instale as dependências:
```bash
   pip install python-nmap streamlit groq python-dotenv
```
5. Execute:
```bash
   python -m streamlit run interface_streamlit.py
```

## Pré-requisitos

O `instalar_e_rodar.bat` instala tudo automaticamente. Para rodar manualmente, você precisa de Python 3.13+, Nmap e uma chave da API do Groq ([console.groq.com](https://console.groq.com)).

## Status

🚧 Em desenvolvimento — MVP em construção.