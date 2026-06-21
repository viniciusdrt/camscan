"""Enumeração segura de identidade de câmeras por protocolos de inventário."""

from __future__ import annotations

import re
import hashlib
import shutil
import socket
import subprocess
import time
from urllib.parse import urlparse

import requests
from requests.auth import HTTPDigestAuth
from onvif import ONVIFCamera
from wsdiscovery.discovery import ThreadedWSDiscovery
from zeep.transports import Transport
from zeroconf import ServiceBrowser, Zeroconf


HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8899}
RTSP_PORTS = {554, 8554}


def _adicionar_unico(lista: list, valor):
    valor = str(valor or "").strip()
    if valor and valor not in lista:
        lista.append(valor)


def descobrir_onvif_ws(ip: str, timeout=4) -> dict:
    resultado = {"xaddrs": [], "scopes": [], "erro": ""}
    wsd = ThreadedWSDiscovery()
    try:
        wsd.start()
        for servico in wsd.searchServices(timeout=timeout):
            xaddrs = [str(x) for x in (servico.getXAddrs() or [])]
            scopes = [str(s) for s in (servico.getScopes() or [])]
            if any(ip in x for x in xaddrs) or any(ip in s for s in scopes):
                for valor in xaddrs:
                    _adicionar_unico(resultado["xaddrs"], valor)
                for valor in scopes:
                    _adicionar_unico(resultado["scopes"], valor)
    except Exception as exc:
        resultado["erro"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            wsd.stop()
        except Exception:
            pass
    return resultado


def descobrir_ssdp(ip: str, timeout=3) -> dict:
    mensagem = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    ).encode("ascii")
    locais = []
    servidor = []
    erro = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.5)
    try:
        sock.sendto(mensagem, ("239.255.255.250", 1900))
        limite = time.monotonic() + timeout
        while time.monotonic() < limite:
            try:
                dados, origem = sock.recvfrom(65535)
            except socket.timeout:
                continue
            texto = dados.decode("utf-8", errors="ignore")
            if origem[0] != ip and ip not in texto:
                continue
            for linha in texto.splitlines():
                nome, separador, valor = linha.partition(":")
                if not separador:
                    continue
                if nome.strip().lower() == "location":
                    _adicionar_unico(locais, valor)
                elif nome.strip().lower() == "server":
                    _adicionar_unico(servidor, valor)
    except OSError as exc:
        erro = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()

    descricoes = []
    for local in locais:
        try:
            destino = urlparse(local)
            if destino.scheme not in {"http", "https"} or destino.hostname != ip:
                continue
            resposta = requests.get(local, timeout=4, stream=True)
            resposta.raise_for_status()
            tamanho = 0
            partes = []
            for parte in resposta.iter_content(8192, decode_unicode=True):
                if isinstance(parte, bytes):
                    parte = parte.decode("utf-8", errors="ignore")
                tamanho += len(parte)
                if tamanho > 100_000:
                    break
                partes.append(parte)
            descricoes.append("".join(partes))
        except requests.RequestException:
            continue
    return {"locations": locais, "servidores": servidor, "descricoes": descricoes, "erro": erro}


class _ListenerMDNS:
    def __init__(self, ip: str):
        self.ip = ip
        self.servicos = []

    def add_service(self, zeroconf, tipo, nome):
        info = zeroconf.get_service_info(tipo, nome, timeout=1000)
        if info and self.ip in info.parsed_addresses():
            self.servicos.append({
                "tipo": tipo,
                "nome": nome,
                "porta": info.port,
                "servidor": info.server or "",
                "propriedades": {
                    k.decode(errors="ignore"): v.decode(errors="ignore")
                    for k, v in info.properties.items()
                },
            })

    def update_service(self, zeroconf, tipo, nome):
        self.add_service(zeroconf, tipo, nome)

    def remove_service(self, zeroconf, tipo, nome):
        pass


def descobrir_mdns(ip: str, timeout=3) -> dict:
    listener = _ListenerMDNS(ip)
    zeroconf = Zeroconf()
    try:
        ServiceBrowser(
            zeroconf,
            ["_http._tcp.local.", "_https._tcp.local.", "_rtsp._tcp.local.", "_onvif._tcp.local."],
            listener,
        )
        time.sleep(timeout)
        return {"servicos": listener.servicos, "erro": ""}
    except Exception as exc:
        return {"servicos": listener.servicos, "erro": f"{type(exc).__name__}: {exc}"}
    finally:
        zeroconf.close()


def fingerprint_http(ip: str, portas: list[int], usuario="", senha="") -> dict:
    respostas = []
    autenticacao = HTTPDigestAuth(usuario, senha) if usuario else None
    for porta in portas:
        if porta not in HTTP_PORTS:
            continue
        esquema = "https" if porta in {443, 8443} else "http"
        url = f"{esquema}://{ip}:{porta}/"
        try:
            resposta = requests.get(url, timeout=7, verify=False, auth=autenticacao)
            titulo = ""
            encontrado = re.search(r"<title[^>]*>(.*?)</title>", resposta.text, re.I | re.S)
            if encontrado:
                titulo = re.sub(r"\s+", " ", encontrado.group(1)).strip()
            respostas.append({
                "url": url,
                "status": resposta.status_code,
                "titulo": titulo,
                "servidor": resposta.headers.get("Server", ""),
                "www_authenticate": resposta.headers.get("WWW-Authenticate", ""),
                "html": resposta.text[:100_000],
            })
        except requests.RequestException as exc:
            respostas.append({"url": url, "erro": f"{type(exc).__name__}: {exc}"})
    return {"respostas": respostas}


def _autorizacao_digest(desafio: str, metodo: str, uri: str, usuario: str, senha: str) -> str:
    realm = re.search(r'realm="([^"]+)"', desafio, re.I)
    nonce = re.search(r'nonce="([^"]+)"', desafio, re.I)
    if not (realm and nonce):
        return ""
    ha1 = hashlib.md5(f"{usuario}:{realm.group(1)}:{senha}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{metodo}:{uri}".encode()).hexdigest()
    resposta = hashlib.md5(f"{ha1}:{nonce.group(1)}:{ha2}".encode()).hexdigest()
    return (
        f'Digest username="{usuario}", realm="{realm.group(1)}", nonce="{nonce.group(1)}", '
        f'uri="{uri}", response="{resposta}"'
    )


def fingerprint_rtsp(ip: str, portas: list[int], usuario="", senha="") -> dict:
    respostas = []
    for porta in portas:
        if porta not in RTSP_PORTS:
            continue
        url = f"rtsp://{ip}:{porta}/"
        requisicao = f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CamScan/1.0\r\n\r\n".encode("ascii")
        try:
            with socket.create_connection((ip, porta), timeout=5) as sock:
                sock.settimeout(5)
                sock.sendall(requisicao)
                partes = []
                while sum(map(len, partes)) < 65535:
                    try:
                        parte = sock.recv(8192)
                    except socket.timeout:
                        break
                    if not parte:
                        break
                    partes.append(parte)
            texto = b"".join(partes).decode("utf-8", errors="ignore")
            if usuario and "401 Unauthorized" in texto:
                autorizacao = _autorizacao_digest(texto, "DESCRIBE", url, usuario, senha)
                if autorizacao:
                    autenticada = (
                        f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n"
                        f"Authorization: {autorizacao}\r\n\r\n"
                    ).encode("ascii")
                    with socket.create_connection((ip, porta), timeout=5) as sock:
                        sock.settimeout(5)
                        sock.sendall(autenticada)
                        partes = []
                        while sum(map(len, partes)) < 65535:
                            try:
                                parte = sock.recv(8192)
                            except socket.timeout:
                                break
                            if not parte:
                                break
                            partes.append(parte)
                    texto += "\n" + b"".join(partes).decode("utf-8", errors="ignore")
            realm = re.search(r'realm="([^"]+)"', texto, re.I)
            respostas.append({"url": url, "resposta": texto, "auth_realm": realm.group(1) if realm else ""})
        except OSError as exc:
            respostas.append({"url": url, "erro": f"{type(exc).__name__}: {exc}"})

        ffprobe = shutil.which("ffprobe")
        # Credenciais nunca são inseridas na linha de comando, que é visível
        # para outros processos. Com autenticação, o cliente RTSP nativo acima é usado.
        if ffprobe and not usuario:
            comando_url = url
            try:
                processo = subprocess.run(
                    [ffprobe, "-v", "error", "-show_entries", "format_tags:stream=codec_name", "-of", "json", comando_url],
                    capture_output=True, text=True, timeout=12, encoding="utf-8", errors="ignore",
                )
                respostas[-1]["ffprobe"] = processo.stdout[:20_000]
            except (OSError, subprocess.TimeoutExpired):
                pass
    return {"respostas": respostas, "ffprobe_disponivel": bool(shutil.which("ffprobe"))}


def obter_info_onvif(ip: str, portas: list[int], xaddrs: list[str], usuario="", senha="") -> dict:
    portas_onvif = []
    for xaddr in xaddrs:
        porta = urlparse(xaddr).port
        if porta:
            _adicionar_unico(portas_onvif, porta)
    for porta in portas:
        if porta in HTTP_PORTS:
            _adicionar_unico(portas_onvif, porta)

    erros = []
    for porta in portas_onvif:
        try:
            transporte = Transport(timeout=5, operation_timeout=7)
            camera = ONVIFCamera(ip, int(porta), usuario, senha, transport=transporte, no_cache=True)
            info = camera.devicemgmt.GetDeviceInformation()
            resultado = {
                "fabricante": str(getattr(info, "Manufacturer", "") or ""),
                "modelo": str(getattr(info, "Model", "") or ""),
                "firmware": str(getattr(info, "FirmwareVersion", "") or ""),
                "serial": str(getattr(info, "SerialNumber", "") or ""),
                "hardware_id": str(getattr(info, "HardwareId", "") or ""),
                "porta": int(porta),
                "erro": "",
            }
            try:
                media = camera.create_media_service()
                perfis = media.GetProfiles()
                resultado["perfis"] = [
                    {"nome": str(getattr(p, "Name", "") or ""), "token": str(getattr(p, "token", "") or "")}
                    for p in perfis
                ]
            except Exception:
                resultado["perfis"] = []
            return resultado
        except Exception as exc:
            erros.append(f"porta {porta}: {type(exc).__name__}: {exc}")
    return {"erro": " | ".join(erros)}


def _extrair_identidade(textos: list[str]) -> dict:
    texto = "\n".join(t for t in textos if t)
    resultado = {"modelo": "", "firmware": ""}
    padroes = {
        "modelo": [r"(?:device[ _-]?model|modelo|model)\s*[\"':=<>/-]+\s*([\w.-]{3,40})"],
        "firmware": [r"(?:firmware(?:version)?|software[ _-]?version|fw)\s*[\"':=<>/-]+\s*([\w.-]{2,40})"],
    }
    for campo, expressoes in padroes.items():
        for expressao in expressoes:
            encontrado = re.search(expressao, texto, re.I)
            if encontrado:
                resultado[campo] = encontrado.group(1).strip(".-_")
                break
    return resultado


def enumerar_dispositivo(camera: dict, usuario="", senha="") -> dict:
    """Retorna uma cópia enriquecida da câmera e mantém erros por fonte para diagnóstico."""
    camera = dict(camera)
    ip = camera["ip"]
    portas = [int(p) for p in camera.get("portas_abertas", [])]

    ws = descobrir_onvif_ws(ip)
    ssdp = descobrir_ssdp(ip)
    mdns = descobrir_mdns(ip)
    http = fingerprint_http(ip, portas, usuario, senha)
    rtsp = fingerprint_rtsp(ip, portas, usuario, senha)
    onvif = obter_info_onvif(ip, portas, ws["xaddrs"], usuario, senha)

    textos = []
    textos.extend(ws["scopes"])
    textos.extend(ssdp["servidores"] + ssdp["descricoes"])
    for item in mdns["servicos"]:
        textos.extend([item["nome"], item["servidor"], " ".join(item["propriedades"].values())])
    for item in http["respostas"]:
        textos.extend([item.get("titulo", ""), item.get("servidor", ""), item.get("html", "")])
    for item in rtsp["respostas"]:
        textos.extend([item.get("resposta", ""), item.get("ffprobe", "")])
    inferida = _extrair_identidade(textos)

    camera["fabricante"] = onvif.get("fabricante") or camera.get("fabricante", "")
    camera["modelo"] = onvif.get("modelo") or inferida["modelo"] or camera.get("modelo", "")
    camera["firmware"] = onvif.get("firmware") or inferida["firmware"] or camera.get("firmware", "")
    camera["serial"] = onvif.get("serial") or camera.get("serial", "")
    camera["hardware_id"] = onvif.get("hardware_id") or camera.get("hardware_id", "")

    produtos = list(camera.get("produtos_detectados", []))
    for item in http["respostas"]:
        _adicionar_unico(produtos, item.get("titulo"))
        _adicionar_unico(produtos, item.get("servidor"))
    for item in ssdp["servidores"]:
        _adicionar_unico(produtos, item)
    camera["produtos_detectados"] = produtos
    camera["enumeracao"] = {
        "onvif_discovery": ws,
        "onvif_device_info": onvif,
        "ssdp": {k: v for k, v in ssdp.items() if k != "descricoes"},
        "mdns": mdns,
        "http": {"respostas": [{k: v for k, v in item.items() if k != "html"} for item in http["respostas"]]},
        "rtsp": rtsp,
    }
    return camera
