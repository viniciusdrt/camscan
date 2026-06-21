# CamScan

O CamScan é uma ferramenta de diagnóstico de segurança para câmeras IP em redes locais autorizadas. Ele descobre equipamentos, avalia serviços expostos, procura vulnerabilidades conhecidas e gera relatórios em linguagem simples.

> Use o CamScan somente em redes e dispositivos próprios ou para os quais você tenha autorização explícita.

## Recursos

- Descoberta de câmeras por Nmap.
- Varredura rápida ou detalhada.
- Enumeração por ONVIF, WS-Discovery, SSDP, mDNS, HTTP e RTSP.
- Testes de segurança com Nuclei.
- Detecção nativa de descrições RTSP acessíveis sem autenticação.
- Auditoria opcional e autorizada de credenciais padrão em HTTP/HTTPS e RTSP.
- Consulta de CVEs na NVD com cache e tratamento de indisponibilidade.
- Bloqueio de CVEs por fabricante quando o modelo não é conhecido, reduzindo falsos positivos.
- Relatório local sem IA.
- Explicações opcionais com a API da Groq.
- Verificação de exposição pública por sonda externa configurável.

## Instalação pelo pacote do release

1. Baixe e extraia completamente o ZIP do release para uma pasta local.
2. Execute `instalar_e_rodar.bat`.
3. Autorize a instalação do Nmap/Npcap caso o Windows solicite.
4. O instalador criará um ambiente virtual, instalará as bibliotecas e verificará o Nuclei.
5. Na primeira execução, ele criará o arquivo `.env` e oferecerá abri-lo.
6. Obtenha sua chave em https://console.groq.com/keys e preencha:

```env
GROQ_API_KEY=sua_chave_aqui
```

Nunca publique ou distribua o arquivo `.env` preenchido. A utilização da IA é opcional e permanece desativada por padrão na interface.

Se ocorrer algum erro, consulte `camscan_instalacao.log`.

## Instalação manual para desenvolvimento

Requisitos:

- Python 3.10 ou superior;
- Nmap 7.99 ou superior com Npcap;
- `nuclei.exe` na raiz do projeto.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
.\.venv\Scripts\python.exe -m streamlit run interface_streamlit.py
```

## Configuração

Variáveis disponíveis no `.env`:

| Variável | Obrigatória | Finalidade |
|---|---:|---|
| `GROQ_API_KEY` | Não | Explicações e relatórios por IA. |
| `NVD_API_KEY` | Não | Aumenta a capacidade de consultas à NVD. |
| `EXTERNAL_PORT_CHECK_URL` | Não | Endpoint externo para verificar portas públicas. |

A sonda externa deve aceitar `GET` com os parâmetros `host` e `port` e retornar:

```json
{"open": true}
```

Sem essa sonda, a exposição pública será apresentada como inconclusiva; o CamScan não usa NAT loopback como prova de exposição.

### Resultado de exposição pública inconclusivo

Quando a interface apresentar mensagens como:

```text
IP público detectado: 189.6.14.219
Nenhuma sonda externa foi configurada. Testar o IP público de dentro da rede não comprova exposição por causa do NAT loopback.
```

isso significa que o CamScan conseguiu identificar o endereço público da conexão, mas não verificou as portas a partir da internet. O resultado não confirma que as câmeras estejam expostas nem que estejam protegidas.

Uma conexão feita de dentro da rede para o próprio IP público pode ser aceita, redirecionada ou bloqueada pelo roteador devido ao NAT loopback, também chamado de NAT hairpin. Por isso, esse teste interno não é usado como evidência de exposição pública.

A conclusão só pode ser obtida com uma sonda executada fora da rede analisada e configurada por meio de `EXTERNAL_PORT_CHECK_URL`. Até essa configuração existir, o estado correto da verificação será **inconclusivo**.

## Como usar

1. Escolha o alcance:
   - apenas rede local;
   - rede local e exposição pública.
2. Escolha a profundidade:
   - **rápida:** prioriza velocidade;
   - **detalhada:** tenta obter modelo e firmware por múltiplos protocolos.
3. Se necessário, ative a auditoria opcional de credenciais padrão.
4. Informe uma rede IPv4 privada de até 256 endereços, como `192.168.0.0/24`.
5. Clique em **Iniciar Scan**.

## Verificação RTSP sem autenticação

Além dos templates do Nuclei, o CamScan possui uma verificação RTSP própria. Para portas `554` e `8554`, ele envia requisições `DESCRIBE` sem credenciais para uma lista limitada de caminhos conhecidos.

Um achado só é registrado quando o servidor retorna `200 OK` e uma descrição SDP contendo informações de sessão e mídia. Respostas `401 Unauthorized`, caminhos inexistentes, timeouts e portas apenas abertas não são tratados como vulnerabilidade.

Essa verificação:

- não tenta usuários ou senhas;
- não baixa nem grava vídeo;
- complementa os resultados do Nuclei;
- envia os achados confirmados para o relatório local ou para a IA, quando ela estiver ativada.

O resultado confirma acesso anônimo à descrição SDP. Ele não executa toda a sequência `SETUP` e `PLAY`, portanto não comprova sozinho a reprodução integral do vídeo.

## Auditoria autorizada de credenciais padrão

A auditoria de credenciais é desativada por padrão e permanece separada da varredura automática. Quando ativada, a interface exige que o usuário:

1. declare que é proprietário dos dispositivos ou possui autorização para testá-los;
2. reconheça o risco de bloqueio ou indisponibilidade temporária;
3. digite `AUTORIZO O TESTE` antes de iniciar o scan.

A execução possui limites fixos:

- somente endereços IPv4 das faixas privadas RFC1918;
- autenticação HTTP/HTTPS Basic ou Digest e RTSP Basic ou Digest;
- lista interna curta de credenciais padrão, sem wordlists fornecidas pelo usuário;
- modo conservador com até 10 tentativas por dispositivo;
- modo ampliado com até 20 tentativas, confirmação adicional e priorização pelo fabricante identificado;
- no máximo cinco tentativas para cada nome de usuário;
- intervalo mínimo de dois segundos entre tentativas;
- interrupção após sucesso ou indicação de bloqueio HTTP `429`;
- nenhuma senha incluída em logs, resultados, relatórios ou linha de comando.

O consentimento é registrado localmente em `.camscan_audit/authorizations.jsonl`. O registro contém data, rede, alvos, protocolos e limites da execução, mas não armazena as credenciais testadas.

Quando uma credencial padrão é aceita, o achado recebe severidade crítica e é encaminhado ao mesmo fluxo de relatórios dos resultados do Nuclei. A primeira versão cobre HTTP/HTTPS e RTSP; autenticação ONVIF ainda não faz parte dessa auditoria.

## CVEs e precisão

A consulta de CVEs só é executada quando o modelo da câmera é identificado. Buscar apenas pelo fabricante gerava resultados de roteadores, telefones e outros produtos; por isso, esse comportamento foi bloqueado.

Mesmo com modelo identificado, uma CVE deve ser confirmada contra:

- modelo exato;
- versão de firmware;
- configuração afetada;
- orientações oficiais do fabricante.

Resultado vazio não garante que o equipamento esteja seguro; significa apenas que as verificações executadas não encontraram problemas.

## Privacidade

- A IA é desativada por padrão.
- Ao ativá-la, IP local, identificação e achados são enviados à API da Groq.
- Sem IA, o relatório é produzido localmente.
- Senhas testadas pela auditoria permanecem apenas em memória durante a tentativa.
- O achado técnico registra protocolo e usuário aceito; relatórios omitem a senha.
- Registros de autorização locais não contêm credenciais.

## Atualizações desta versão — junho de 2026

Esta versão inclui:

- dois níveis de profundidade de varredura;
- opção separada para rede local e exposição pública;
- enumeração avançada além do Nmap;
- detecção de streams RTSP que fornecem SDP sem autenticação;
- auditoria autorizada e limitada de credenciais padrão em HTTP/HTTPS e RTSP;
- consulta NVD resiliente a timeout, com retry e cache local;
- redução de falsos positivos por correspondência obrigatória do modelo;
- seção exclusiva com detalhes e explicações de CVEs;
- relatório geral simplificado, exibindo somente a quantidade de CVEs;
- IA opcional com consentimento explícito;
- relatório local quando a Groq estiver desativada ou indisponível;
- validação de redes privadas e limite máximo de `/24`;
- suporte correto a HTTP, HTTPS e RTSP no Nuclei;
- timeout e tratamento de erros do Nuclei;
- proteção contra SSRF em respostas SSDP;
- correção da verificação de exposição pública;
- instalador novo com ambiente virtual e log automático;
- instalação validada do Python e do Nmap 7.99;
- correções na execução do Nuclei pelo PowerShell;
- atualização automática de templates do Nuclei sem interromper a instalação em caso de falha de rede.

## Testes

No repositório de desenvolvimento:

```powershell
python -m unittest discover -s tests -v
```

A versão atual possui testes para descoberta, CVEs, relatórios, enumeração, exposição pública, execução do Nuclei, RTSP sem autenticação e auditoria de credenciais padrão.

## Organização dos módulos

- `modules/discovery.py`: descoberta e identificação inicial dos dispositivos.
- `modules/device_enumeration.py`: enumeração HTTP, RTSP, ONVIF e protocolos de descoberta.
- `modules/vulnerability_assessment.py`: Nuclei e verificação RTSP sem autenticação.
- `modules/default_credentials.py`: consentimento, limites e auditoria de credenciais padrão.
- `modules/cve_lookup.py`: consulta e filtragem de CVEs.
- `modules/llm_response.py`: geração do relatório local ou por IA.

## Tecnologias

- Python
- Streamlit
- Nmap e Npcap
- Nuclei
- ONVIF/WS-Discovery
- SSDP e mDNS
- NVD
- Groq API
