"""Consulta de CVEs potencialmente relacionados aos equipamentos descobertos."""

from __future__ import annotations

import os
import re
import time
import hashlib
import json
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv


load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTADOS = 20
RESULTADOS_POR_CONSULTA = 20
CACHE_TTL_SEGUNDOS = 24 * 60 * 60
CACHE_DIR = Path(__file__).resolve().parent.parent / ".camscan_cache" / "nvd"
TERMOS_GENERICOS = {
    "camera", "câmera", "webcam", "ip", "rtsp", "rtspd", "http", "httpd",
    "server", "service", "device", "dvr", "nvr",
}


def _texto(valor: Any) -> str:
    return " ".join(str(valor or "").split()).strip()


def _termos_busca(camera: dict) -> list[str]:
    fabricante = _texto(camera.get("fabricante"))
    modelo = _texto(camera.get("modelo"))
    produto = _texto(camera.get("produto_rtsp"))
    versao = _texto(camera.get("versao_rtsp") or camera.get("firmware"))
    produtos_detectados = [_texto(p) for p in camera.get("produtos_detectados", []) if _texto(p)]

    candidatos = []
    # Consultas compostas têm prioridade e reduzem falsos positivos.
    if fabricante and modelo:
        candidatos.append(f"{fabricante} {modelo}")
    elif fabricante:
        candidatos.append(fabricante)
    if fabricante and produto and fabricante.lower() in produto.lower():
        candidatos.append(f"{fabricante} {produto}")
    elif produto:
        candidatos.append(produto)
    for produto_detectado in produtos_detectados:
        palavras = [
            p for p in produto_detectado.split()
            if p.casefold() not in TERMOS_GENERICOS
        ]
        produto_util = " ".join(palavras)
        if produto_util and produto_util.casefold() != fabricante.casefold():
            candidatos.append(produto_util)
    if modelo and modelo.lower() not in fabricante.lower():
        candidatos.append(modelo)
    if versao and (modelo or produto):
        candidatos.append(f"{modelo or produto} {versao}")

    termos = []
    for termo in candidatos:
        termo = _texto(termo)
        if len(termo) >= 3 and termo.casefold() not in {t.casefold() for t in termos}:
            termos.append(termo)
    return termos[:3]


def _descricao(cve: dict) -> str:
    descricoes = cve.get("descriptions") or []
    for idioma in ("pt-BR", "pt", "en"):
        for item in descricoes:
            if item.get("lang") == idioma and item.get("value"):
                return item["value"]
    return next((d.get("value") for d in descricoes if d.get("value")), "Sem descrição disponível.")


def _cvss(cve: dict) -> tuple[str, float | None]:
    metricas = cve.get("metrics") or {}
    for chave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metrica in metricas.get(chave) or []:
            dados = metrica.get("cvssData") or {}
            score = dados.get("baseScore")
            severidade = dados.get("baseSeverity") or metrica.get("baseSeverity")
            if score is not None:
                if not severidade:
                    severidade = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                return str(severidade).lower(), float(score)
    return "unknown", None


def _tokens_identidade(camera: dict) -> set[str]:
    texto = " ".join(_texto(camera.get(campo)) for campo in ("fabricante", "modelo", "produto_rtsp"))
    texto += " " + " ".join(_texto(p) for p in camera.get("produtos_detectados", []))
    return {t.casefold() for t in re.findall(r"[\w.-]{3,}", texto) if t.casefold() not in TERMOS_GENERICOS}


def _modelo_corresponde(descricao: str, modelo: str) -> bool:
    """Compara modelo ignorando hífens/espaços, mas exige todos os componentes úteis."""
    componentes = [
        parte.casefold()
        for parte in re.findall(r"[A-Za-z0-9]+", _texto(modelo))
        if len(parte) >= 2 and parte.casefold() not in TERMOS_GENERICOS
    ]
    if not componentes:
        return False
    palavras_descricao = set(re.findall(r"[a-z0-9]+", descricao.casefold()))
    return all(componente in palavras_descricao for componente in componentes)


def _arquivo_cache(termo: str) -> Path:
    chave = hashlib.sha256(termo.casefold().encode("utf-8")).hexdigest()
    return CACHE_DIR / f"{chave}.json"


def _ler_cache(termo: str, aceitar_expirado=False):
    arquivo = _arquivo_cache(termo)
    try:
        conteudo = json.loads(arquivo.read_text(encoding="utf-8"))
        idade = time.time() - float(conteudo["salvo_em"])
        if aceitar_expirado or idade <= CACHE_TTL_SEGUNDOS:
            return conteudo["dados"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def _salvar_cache(termo: str, dados: dict):
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _arquivo_cache(termo).write_text(
            json.dumps({"salvo_em": time.time(), "dados": dados}, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass


def _consultar_nvd(session, termo: str, headers: dict, usar_cache=True):
    """Consulta com retry e usa a última resposta válida durante oscilações da NVD."""
    if usar_cache:
        dados_cache = _ler_cache(termo)
        if dados_cache is not None:
            return dados_cache, True

    ultimo_erro = None
    for tentativa in range(3):
        try:
            resposta = session.get(
                NVD_URL,
                params={"keywordSearch": termo, "resultsPerPage": RESULTADOS_POR_CONSULTA},
                headers=headers,
                timeout=(8, 20),
            )
            if resposta.status_code in {429, 500, 502, 503, 504} and tentativa < 2:
                espera = resposta.headers.get("Retry-After")
                time.sleep(min(float(espera) if espera and espera.isdigit() else 3, 6))
                continue
            resposta.raise_for_status()
            dados = resposta.json()
            if usar_cache:
                _salvar_cache(termo, dados)
            return dados, False
        except (requests.ReadTimeout, requests.ConnectionError) as exc:
            ultimo_erro = exc
            if tentativa < 2:
                time.sleep(2)
                continue
            break

    if usar_cache:
        dados_cache = _ler_cache(termo, aceitar_expirado=True)
        if dados_cache is not None:
            return dados_cache, True
    if ultimo_erro:
        raise ultimo_erro
    resposta.raise_for_status()
    return resposta.json(), False


def consultar_cves(camera: dict, session=requests) -> dict:
    """Retorna achados e diagnóstico sem confundir falha de API com resultado vazio."""
    modelo = _texto(camera.get("modelo"))
    if not modelo:
        return {
            "status": "identificacao_insuficiente",
            "achados": [],
            "erros": [],
            "termos": [],
            "cache_utilizado": False,
            "motivo": "O modelo da câmera não foi identificado; busca apenas por fabricante foi bloqueada para evitar falsos positivos.",
        }

    termos = _termos_busca(camera)
    if not termos:
        return {"status": "sem_identificacao", "achados": [], "erros": [], "termos": []}

    headers = {"User-Agent": "CamScan/1.0"}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    achados_por_id = {}
    erros = []
    cache_utilizado = False
    tokens = _tokens_identidade(camera)
    for termo in termos:
        try:
            dados, veio_do_cache = _consultar_nvd(
                session, termo, headers, usar_cache=session is requests
            )
            cache_utilizado = cache_utilizado or veio_do_cache
        except (requests.RequestException, ValueError) as exc:
            erros.append(f"{termo}: {exc}")
            continue

        for item in dados.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            codigo = cve.get("id")
            if not codigo:
                continue
            descricao = _descricao(cve)
            texto_cve = descricao.casefold()
            correspondencias = sorted(t for t in tokens if t in texto_cve)
            # Resultados de uma consulta ampla por fabricante precisam mencionar
            # ao menos um identificador do equipamento na descrição.
            if tokens and not correspondencias:
                continue
            # Quando há modelo, citar apenas o fabricante não é suficiente.
            if not _modelo_corresponde(descricao, modelo):
                continue
            severidade, score = _cvss(cve)
            achados_por_id[codigo] = {
                "ip": camera.get("ip", ""),
                "template_id": codigo,
                "nome": codigo,
                "severidade": severidade,
                "cvss": score,
                "descricao": descricao,
                "encontrado_em": f"https://nvd.nist.gov/vuln/detail/{codigo}",
                "termo_busca": termo,
                "correspondencias": correspondencias,
                "confirmado": False,
            }

    status = "parcial" if erros and achados_por_id else "erro" if erros else "ok"
    achados = sorted(
        achados_por_id.values(),
        key=lambda item: (item["cvss"] is not None, item["cvss"] or -1),
        reverse=True,
    )[:MAX_RESULTADOS]
    return {
        "status": status,
        "achados": achados,
        "erros": erros,
        "termos": termos,
        "cache_utilizado": cache_utilizado,
    }


def buscar_cves(camera: dict) -> list:
    """API compatível com o código anterior; prefira ``consultar_cves`` na UI."""
    return consultar_cves(camera)["achados"]
