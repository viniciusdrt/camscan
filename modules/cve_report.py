"""Relatório explicativo e detalhes técnicos dos CVEs encontrados."""

from __future__ import annotations

import os

from groq import Groq


def _identificacao(camera: dict) -> str:
    campos = (
        camera.get("fabricante"),
        camera.get("modelo"),
        camera.get("produto_rtsp"),
        camera.get("versao_rtsp") or camera.get("firmware"),
    )
    return " | ".join(str(valor) for valor in campos if valor) or "não identificada"


def montar_dados_para_ia(camera: dict, cves: list[dict]) -> str:
    linhas = [
        f"Câmera: {camera.get('ip', 'desconhecida')}",
        f"Identificação detectada: {_identificacao(camera)}",
        "CVEs candidatos encontrados na NVD:",
    ]
    for cve in cves:
        descricao = str(cve.get("descricao", "Sem descrição"))[:1200]
        linhas.append(
            f"- {cve.get('template_id')} | CVSS: {cve.get('cvss', 'não informado')} | "
            f"Severidade: {cve.get('severidade', 'unknown')} | Descrição NVD: {descricao}"
        )
    return "\n".join(linhas)


def gerar_explicacao_cves(camera: dict, cves: list[dict], usar_ia=False) -> str:
    """Explica todos os CVEs em uma chamada; nunca substitui os dados da NVD."""
    if not cves:
        return "Nenhum CVE foi localizado para esta câmera."

    if not usar_ia:
        return (
            "A explicação por IA está desativada. Os dados técnicos oficiais da NVD "
            "continuam disponíveis abaixo sem envio de informações a terceiros."
        )

    chave_api = os.getenv("GROQ_API_KEY")
    if not chave_api:
        return (
            "A explicação por IA não está disponível porque `GROQ_API_KEY` não foi configurada. "
            "Os detalhes técnicos da NVD permanecem disponíveis abaixo."
        )

    prompt = """
Você é um analista de segurança especializado em câmeras IP. Explique em português do Brasil
os CVEs fornecidos para uma pessoa sem conhecimento técnico.

Regras obrigatórias:
- Comece avisando que os resultados são potenciais: fabricante/modelo/firmware precisam coincidir.
- Não invente fatos, versões afetadas, exploits, correções ou impactos ausentes na descrição da NVD.
- Não diga que a câmera está vulnerável; diga que ela pode estar afetada e como confirmar.
- Crie uma seção curta para CADA código CVE, sem omitir ou agrupar códigos.
- Em cada seção inclua: o que é, impacto possível, gravidade/CVSS e ação recomendada.
- Se a descrição não trouxer informação suficiente, declare isso claramente.
- Termine com passos práticos priorizados para confirmar modelo, firmware e atualização disponível.
"""
    try:
        resposta = Groq(api_key=chave_api).chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": montar_dados_para_ia(camera, cves)},
            ],
            temperature=0.2,
            max_tokens=7000,
        )
        return resposta.choices[0].message.content
    except Exception as exc:
        return (
            "A explicação por IA não pôde ser gerada nesta execução. "
            f"Detalhe: `{type(exc).__name__}: {exc}`\n\n"
            "Consulte os dados técnicos da NVD abaixo."
        )


def montar_detalhes_tecnicos(cves: list[dict]) -> str:
    """Gera Markdown confiável diretamente dos dados retornados pela NVD."""
    blocos = [
        "### Dados técnicos da NVD",
        "Os itens abaixo são candidatos e não confirmam que o firmware instalado seja afetado.",
    ]
    for cve in cves:
        codigo = cve.get("template_id", "CVE desconhecido")
        score = cve.get("cvss")
        cvss = f"{score:.1f}" if isinstance(score, (int, float)) else "não informado"
        correspondencias = ", ".join(cve.get("correspondencias") or []) or "não informadas"
        url = cve.get("encontrado_em", "")
        blocos.extend([
            "---",
            f"#### {codigo}",
            f"- **Severidade:** {str(cve.get('severidade', 'unknown')).upper()}",
            f"- **Pontuação CVSS:** {cvss}",
            f"- **Termo consultado:** {cve.get('termo_busca', 'não informado')}",
            f"- **Correspondências encontradas:** {correspondencias}",
            f"- **Status:** potencial; modelo e firmware ainda precisam ser confirmados",
            f"- **Fonte:** [registro oficial na NVD]({url})" if url else "- **Fonte:** não informada",
            "",
            f"**Descrição publicada:** {cve.get('descricao', 'Sem descrição disponível.')}",
        ])
    return "\n".join(blocos)
