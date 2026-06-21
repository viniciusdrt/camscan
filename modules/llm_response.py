from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()


def eh_cve(achado: dict) -> bool:
    """
    Verifica se um achado parece ser uma CVE.
    """
    template_id = str(achado.get("template_id", "")).upper()
    nome = str(achado.get("nome", "")).upper()

    return template_id.startswith("CVE-") or nome.startswith("CVE-")


def obter_codigo_cve(achado: dict) -> str:
    """
    Retorna o código CVE do achado, quando existir.
    """
    template_id = str(achado.get("template_id", ""))
    nome = str(achado.get("nome", ""))

    if template_id.upper().startswith("CVE-"):
        return template_id

    if nome.upper().startswith("CVE-"):
        return nome

    return ""


def montar_lista_cves(achados: list) -> str:
    """
    Cria uma lista técnica simples com os CVEs encontrados.
    Essa parte é adicionada ao final do relatório para garantir
    que os códigos apareçam na interface.
    """
    cves = []

    for achado in achados:
        codigo = obter_codigo_cve(achado)

        if codigo and codigo not in cves:
            cves.append(codigo)

    if not cves:
        return ""

    linhas = [
        "",
        "6. REFERÊNCIAS TÉCNICAS DAS FALHAS CONHECIDAS",
        "",
        "Estes códigos foram localizados por semelhança com a identificação do equipamento e precisam ser confirmados pelo modelo e firmware:",
    ]

    for codigo in cves:
        linhas.append(f"- {codigo}")

    linhas.append("")
    linhas.append(
        "Esses códigos servem para consulta técnica pelo responsável de TI ou pelo suporte do fabricante."
    )

    return "\n".join(linhas)


def _relatorio_local(ip: str, achados: list, quantidade_cves: int) -> str:
    pesos = {"info": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    maior = max((pesos.get(str(a.get("severidade", "unknown")).lower(), 0) for a in achados), default=0)
    classificacoes = {
        0: "✅ SEGURA nas verificações executadas",
        1: "⚠️ PODE MELHORAR",
        2: "🔴 VULNERÁVEL",
        3: "🚨 CRÍTICA",
        4: "🚨 CRÍTICA",
    }
    linhas = [
        f"### 1. Classificação\n{classificacoes[maior]}",
        "### 2. Resumo geral",
        f"Foram encontrados {len(achados)} problema(s) pela varredura.",
    ]
    if quantidade_cves:
        linhas.append(f"Também foram localizadas {quantidade_cves} CVE(s) potenciais; veja a seção específica.")
    linhas.append("### 3. O que encontramos")
    if not achados:
        linhas.append("Nenhum problema foi encontrado pelas verificações executadas.")
    for achado in achados:
        linhas.append(
            f"- **{achado.get('nome', 'Achado')}** "
            f"({achado.get('severidade', 'unknown')}): {achado.get('descricao', 'Sem descrição')}"
        )
    linhas.extend([
        "### 4. O que você deve fazer",
        "Mantenha o firmware atualizado, use uma senha forte e revise periodicamente a exposição da câmera.",
        "### 5. Conclusão",
        f"Relatório local da câmera {ip}, gerado sem enviar dados a serviços de IA.",
    ])
    return "\n\n".join(linhas)


def processar_resultados(resultados: list, cameras: list | None = None, usar_ia=False) -> dict:
    cameras_por_ip = {camera["ip"]: [] for camera in (cameras or [])}

    for achado in resultados:
        ip = achado["ip"]

        if ip not in cameras_por_ip:
            cameras_por_ip[ip] = []

        cameras_por_ip[ip].append(achado)

    relatorios = {}

    for ip, achados in cameras_por_ip.items():
        cves = [achado for achado in achados if eh_cve(achado)]
        outros_achados = [achado for achado in achados if not eh_cve(achado)]
        linhas = [
            f"Câmera: {ip}",
            "",
            "Problemas encontrados:" if achados else "Nenhum problema foi encontrado pelas verificações executadas.",
        ]

        for achado in outros_achados:
            linhas.append(
                "- Tipo: Achado da varredura | "
                f"Severidade: {achado.get('severidade', 'unknown')} | "
                f"Nome: {achado.get('nome', 'Sem nome')} | "
                f"Descrição: {achado.get('descricao', 'Sem descrição')}"
            )

        if cves:
            linhas.append(
                f"- Foram encontradas {len(cves)} CVE(s) potencialmente relacionada(s). "
                "Não apresente códigos nem detalhes neste relatório; eles estão na seção específica de CVEs."
            )

        mensagem = "\n".join(linhas)

        if usar_ia:
            try:
                relatorios[ip] = resposta_chatbot(mensagem)
            except Exception:
                relatorios[ip] = _relatorio_local(ip, outros_achados, len(cves))
        else:
            relatorios[ip] = _relatorio_local(ip, outros_achados, len(cves))

    return relatorios


def resposta_chatbot(mensagem: str) -> str:
    chave_api = os.getenv("GROQ_API_KEY")

    if not chave_api:
        return (
            "Erro: a chave da API da Groq não foi encontrada.\n\n"
            "Verifique se o arquivo .env contém a variável GROQ_API_KEY."
        )

    client = Groq(api_key=chave_api)

    system_prompt = """
Você é um assistente de segurança digital especializado em câmeras IP.

Seu trabalho é analisar os resultados de uma varredura de segurança e gerar um relatório SIMPLES, CLARO e HUMANO para o dono de uma pequena empresa, condomínio ou clínica — alguém que não entende de tecnologia.

Os achados podem vir de duas fontes diferentes:
- Varredura local, que encontra problemas dentro da rede interna
- Uma contagem de CVEs potenciais. Neste relatório mencione SOMENTE a quantidade; os detalhes ficam em outra seção da interface.

Trate cada tipo com a devida importância sem afirmar riscos que não foram confirmados.

CLASSIFICAÇÃO OBRIGATÓRIA:
- ✅ SEGURA — Todos os achados são informativos, sem risco real.
- ⚠️ PODE MELHORAR — O achado mais grave é "low".
- 🔴 VULNERÁVEL — O achado mais grave é "medium".
- 🚨 CRÍTICA — O achado mais grave é "high" ou "critical".

ESTRUTURA DO RELATÓRIO:

1. CLASSIFICAÇÃO
Informe o nível com emoji e nome.

2. RESUMO GERAL
Escreva 2 a 3 frases simples explicando a situação. Sem exagero e sem termos difíceis.

3. O QUE ENCONTRAMOS
Para cada problema encontrado, explique:
- Nome simples do problema
- O que significa na prática
- Urgência

Quando houver CVEs, informe apenas quantos resultados potenciais foram encontrados e diga que as explicações estão na seção "Detalhes das CVEs". Não cite códigos, CVSS, descrições técnicas ou detalhes individuais neste primeiro relatório.

4. O QUE VOCÊ DEVE FAZER
Crie uma lista numerada do mais urgente ao menos urgente.
Use ações concretas e simples.

5. CONCLUSÃO
Escreva uma frase encorajadora e direta.

REGRAS:
- Responda sempre em português do Brasil.
- Use linguagem simples.
- Evite termos técnicos desnecessários.
- Use a palavra CVE apenas para informar a quantidade encontrada.
- Não explique CVEs individualmente neste relatório.
- Tom: calmo, direto e prestativo.
"""

    resposta = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": mensagem}
        ]
    )

    return resposta.choices[0].message.content
