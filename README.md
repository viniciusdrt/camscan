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

## Status

🚧 Em desenvolvimento — MVP em construção.