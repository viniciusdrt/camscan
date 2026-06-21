import json
import ipaddress
import re

import nmap

from modules.device_enumeration import enumerar_dispositivo


PORTAS = "80,443,554,8000,8080,8443,8554"
REDES_PRIVADAS = tuple(ipaddress.ip_network(valor) for valor in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validar_rede(valor: str):
    try:
        rede = ipaddress.ip_network(str(valor).strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Informe uma rede CIDR válida, por exemplo 192.168.0.0/24.") from exc
    if rede.version != 4 or not any(rede.subnet_of(privada) for privada in REDES_PRIVADAS):
        raise ValueError("Somente redes IPv4 privadas podem ser verificadas.")
    if rede.num_addresses > 256:
        raise ValueError("A rede pode conter no máximo 256 endereços (/24).")
    return rede


def _servico(tcp: dict, porta: int) -> dict:
    return tcp.get(porta, {})


def _modelo_e_firmware(dados: dict) -> tuple[str, str]:
    textos = []
    for info in dados.get("tcp", {}).values():
        textos.extend(str(info.get(campo, "")) for campo in ("product", "version", "extrainfo"))
        textos.extend(str(v) for v in (info.get("script") or {}).values())
    banner = " ".join(textos)
    modelo = ""
    firmware = ""
    padrao_modelo = re.search(r"(?:model|modelo)[\s:=/-]+([\w.-]{3,40})", banner, re.I)
    padrao_firmware = re.search(r"(?:firmware|fw)[\s:=/-]+([\w.-]{2,40})", banner, re.I)
    if padrao_modelo:
        modelo = padrao_modelo.group(1)
    if padrao_firmware:
        firmware = padrao_firmware.group(1)
    return modelo, firmware


def _enriquecer_host(ip: str, dados_base: dict, profundidade: str) -> dict:
    """Coleta banners sem permitir que um timeout apague a descoberta básica."""
    if profundidade == "rapida":
        return dados_base

    combinado = dict(dados_base)
    tcp_combinado = {porta: dict(info) for porta, info in dados_base.get("tcp", {}).items()}
    portas_abertas = [porta for porta, info in tcp_combinado.items() if info.get("state") == "open"]

    # Cada porta é analisada isoladamente. Assim, um RTSP lento não apaga os
    # banners HTTP que já tenham sido identificados.
    for porta in portas_abertas:
        scripts = "rtsp-methods,banner" if porta in (554, 8554) else "http-title,http-headers,banner"
        scanner = nmap.PortScanner()
        try:
            scanner.scan(
                hosts=ip,
                ports=str(porta),
                arguments=(
                    "-Pn -sV --version-all -T3 --max-retries 2 --host-timeout 50s "
                    f"--script-timeout 10s --script={scripts}"
                ),
            )
        except nmap.PortScannerError:
            continue
        if ip not in scanner.all_hosts():
            continue
        info_detalhada = scanner[ip].get("tcp", {}).get(porta)
        if info_detalhada:
            tcp_combinado[porta] = info_detalhada

    combinado["tcp"] = tcp_combinado
    return combinado


def escanear_rede(ipgeral, profundidade="rapida", usuario="", senha=""):
    if profundidade not in {"rapida", "detalhada"}:
        raise ValueError("profundidade deve ser 'rapida' ou 'detalhada'")

    rede = validar_rede(ipgeral)
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=str(rede),
        ports=PORTAS,
        arguments="-T4 --max-retries 1",
    )
    cameras = []
    for ip in scanner.all_hosts():
        dados_base = scanner[ip]
        tcp = dados_base.get("tcp", {})
        rtsp_aberto = any(_servico(tcp, p).get("state") == "open" for p in (554, 8554))
        produtos = " ".join(str(v.get("product", "")) for v in tcp.values()).lower()
        parece_camera = any(p in produtos for p in ("camera", "webcam", "rtsp", "dvr", "nvr"))
        if not (rtsp_aberto or parece_camera):
            continue

        dados = _enriquecer_host(ip, dados_base, profundidade)
        tcp_detalhado = dados.get("tcp", {})
        # Se o enriquecimento não conservou a porta, mantenha o resultado rápido.
        tcp = tcp_detalhado if any(info.get("state") == "open" for info in tcp_detalhado.values()) else tcp
        mac = dados.get("addresses", {}).get("mac", "")
        fabricante = dados.get("vendor", {}).get(mac, "")
        porta_rtsp = 554 if _servico(tcp, 554).get("state") == "open" else 8554
        rtsp = _servico(tcp, porta_rtsp)
        modelo, firmware = _modelo_e_firmware(dados)
        camera = {
            "ip": ip,
            "mac": mac,
            "fabricante": fabricante,
            "modelo": modelo,
            "firmware": firmware,
            "portas_abertas": [p for p, info in tcp.items() if info.get("state") == "open"],
            "produto_rtsp": rtsp.get("product", ""),
            "versao_rtsp": rtsp.get("version", ""),
            "produtos_detectados": sorted({
                str(info.get("product", "")).strip()
                for info in tcp.values() if str(info.get("product", "")).strip()
            }),
            "servicos": {
                p: {k: info.get(k, "") for k in ("name", "product", "version", "extrainfo")}
                for p, info in tcp.items() if info.get("state") == "open"
            },
        }
        if profundidade == "detalhada":
            camera = enumerar_dispositivo(camera, usuario=usuario, senha=senha)
        cameras.append(camera)
    return cameras


if __name__ == "__main__":
    mascara = input("Digite sua máscara de rede: ")
    print(json.dumps(escanear_rede(mascara, profundidade="detalhada"), indent=2, ensure_ascii=False))
