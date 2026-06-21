"""Verificação de exposição usando uma sonda realmente externa configurável."""

import ipaddress
import os

import requests


PORTAS_PUBLICAS = (80, 443, 554, 8000, 8080, 8443, 8554)


def descobre_ip_publico():
    try:
        resposta = requests.get("https://api.ipify.org", timeout=5)
        resposta.raise_for_status()
        ip = str(ipaddress.ip_address(resposta.text.strip()))
        return ip
    except (requests.RequestException, ValueError):
        return None


def verificar_exposicao_publica(ip, session=requests):
    """A sonda deve aceitar GET com ``host``/``port`` e retornar ``{"open": bool}``."""
    url_sonda = os.getenv("EXTERNAL_PORT_CHECK_URL", "").strip()
    if not url_sonda:
        return {
            "status": "inconclusivo",
            "achados": [],
            "erros": [],
            "mensagem": (
                "Nenhuma sonda externa foi configurada. Testar o IP público de dentro da rede "
                "não comprova exposição por causa do NAT loopback."
            ),
        }

    achados = []
    erros = []
    for porta in PORTAS_PUBLICAS:
        try:
            resposta = session.get(url_sonda, params={"host": ip, "port": porta}, timeout=10)
            resposta.raise_for_status()
            aberto = resposta.json().get("open")
            if aberto is True:
                achados.append({
                    "ip": ip,
                    "template_id": "porta-publica-acessivel",
                    "nome": "Porta acessível pela internet",
                    "severidade": "high",
                    "descricao": (
                        f"A porta {porta} respondeu a uma sonda externa no IP {ip}. "
                        "Confirme no roteador para qual dispositivo o redirecionamento aponta."
                    ),
                    "encontrado_em": f"{ip}:{porta}",
                })
            elif aberto is not False:
                erros.append(f"porta {porta}: resposta sem campo booleano 'open'")
        except (requests.RequestException, ValueError) as exc:
            erros.append(f"porta {porta}: {exc}")

    status = "parcial" if erros else "ok"
    return {"status": status, "achados": achados, "erros": erros, "mensagem": ""}


if __name__ == "__main__":
    ip = descobre_ip_publico()
    print(ip, verificar_exposicao_publica(ip) if ip else "IP público indisponível")
