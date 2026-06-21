"""Auditoria controlada de credenciais padrão em câmeras autorizadas."""

from __future__ import annotations

import base64
import json
import hashlib
import ipaddress
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth


HTTP_PORTS = {80: "http", 443: "https", 8000: "http", 8080: "http", 8443: "https"}
RTSP_PORTS = {554, 8554}
RTSP_PATHS = ("/", "/live", "/stream", "/stream1", "/Streaming/Channels/101")
DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
)
EXPANDED_CREDENTIALS = (
    ("admin", "password"),
    ("root", "admin"),
    ("root", "password"),
    ("root", "12345"),
    ("root", "123456"),
    ("user", "user"),
    ("user", "12345"),
    ("user", "password"),
    ("user", ""),
    ("user", "123456"),
    ("administrator", "admin"),
    ("administrator", "password"),
    ("administrator", "12345"),
    ("service", "service"),
    ("guest", "guest"),
)
VENDOR_CREDENTIALS = {
    "hikvision": (("admin", "12345"),),
    "dahua": (("admin", "admin"),),
    "intelbras": (("admin", "admin"), ("admin", "")),
    "axis": (("root", "pass"),),
    "foscam": (("admin", ""),),
    "tp-link": (("admin", "admin"),),
}
MAX_ATTEMPTS_CONSERVATIVE = 10
MAX_ATTEMPTS_EXPANDED = 20
MAX_ATTEMPTS_PER_USERNAME = 5
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def record_authorization(
    network: str,
    devices: list[dict],
    *,
    max_attempts: int = MAX_ATTEMPTS_CONSERVATIVE,
    base_dir: str | Path | None = None,
) -> Path:
    """Registra o consentimento sem armazenar credenciais ou resultados sensíveis."""
    root = Path(base_dir) if base_dir else Path(__file__).resolve().parents[1] / ".camscan_audit"
    root.mkdir(parents=True, exist_ok=True)
    target = root / "authorizations.jsonl"
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "network": str(network),
        "targets": [str(device.get("ip", "")) for device in devices],
        "protocols": ["HTTP", "HTTPS", "RTSP"],
        "max_attempts_per_device": max_attempts,
        "max_attempts_per_username": MAX_ATTEMPTS_PER_USERNAME,
        "minimum_interval_seconds": 2,
        "authorization_confirmed": True,
    }
    with target.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")
    return target


def _private_ip(ip: str) -> bool:
    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return endereco.version == 4 and any(endereco in network for network in PRIVATE_IPV4_NETWORKS)


def _credentials_for_camera(camera: dict, expanded: bool) -> tuple[tuple[str, str], ...]:
    identity = " ".join(
        str(camera.get(field, "")) for field in ("fabricante", "modelo", "produto_rtsp")
    ).lower()
    candidates = []
    if expanded:
        for vendor, credentials in VENDOR_CREDENTIALS.items():
            if vendor in identity:
                candidates.extend(credentials)
    candidates.extend(DEFAULT_CREDENTIALS)
    if expanded:
        candidates.extend(EXPANDED_CREDENTIALS)

    selected = []
    per_username = {}
    limit = MAX_ATTEMPTS_EXPANDED if expanded else MAX_ATTEMPTS_CONSERVATIVE
    for credential in candidates:
        if credential in selected:
            continue
        username = credential[0]
        if per_username.get(username, 0) >= MAX_ATTEMPTS_PER_USERNAME:
            continue
        selected.append(credential)
        per_username[username] = per_username.get(username, 0) + 1
        if len(selected) >= limit:
            break
    return tuple(selected)


def _finding(ip: str, protocol: str, endpoint: str, username: str) -> dict:
    return {
        "ip": ip,
        "template_id": "default-credentials-valid",
        "nome": "Credencial padrão aceita pela câmera",
        "severidade": "critical",
        "descricao": (
            f"O serviço {protocol} aceitou uma combinação conhecida de credenciais padrão. "
            "A senha foi omitida do resultado; altere imediatamente as credenciais do dispositivo."
        ),
        "encontrado_em": endpoint,
        "protocolo": protocol,
        "usuario": username,
    }


def _reserve_attempt(username: str, attempts_by_username: dict[str, int]) -> bool:
    if attempts_by_username.get(username, 0) >= MAX_ATTEMPTS_PER_USERNAME:
        return False
    attempts_by_username[username] = attempts_by_username.get(username, 0) + 1
    return True


def _audit_http(
    camera: dict,
    budget: int,
    credentials: tuple[tuple[str, str], ...],
    attempts_by_username: dict[str, int],
    interval: float,
    sleep,
    session,
) -> tuple[list, int, bool]:
    ip = camera["ip"]
    attempts = 0
    for port in camera.get("portas_abertas", []):
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        scheme = HTTP_PORTS.get(port)
        if not scheme:
            continue
        endpoint = f"{scheme}://{ip}:{port}/"
        try:
            baseline = session.get(endpoint, timeout=4, verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        if baseline.status_code != 401:
            continue
        challenge = baseline.headers.get("WWW-Authenticate", "").lower()
        if "digest" in challenge:
            auth_factory = HTTPDigestAuth
        elif "basic" in challenge:
            auth_factory = HTTPBasicAuth
        else:
            continue

        for username, password in credentials:
            if attempts >= budget:
                return [], attempts, False
            if not _reserve_attempt(username, attempts_by_username):
                continue
            if attempts:
                sleep(interval)
            attempts += 1
            try:
                response = session.get(
                    endpoint,
                    auth=auth_factory(username, password),
                    timeout=4,
                    verify=False,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue
            if response.status_code == 429:
                return [], attempts, True
            if response.status_code not in {401, 403} and response.status_code < 500:
                return [_finding(ip, scheme.upper(), endpoint, username)], attempts, False
    return [], attempts, False


def _rtsp_request(ip: str, port: int, path: str, authorization: str = "", timeout=3) -> tuple[str, str]:
    endpoint = f"rtsp://{ip}:{port}{path}"
    authorization_header = f"Authorization: {authorization}\r\n" if authorization else ""
    payload = (
        f"DESCRIBE {endpoint} RTSP/1.0\r\n"
        "CSeq: 1\r\nAccept: application/sdp\r\n"
        f"{authorization_header}User-Agent: CamScan/1.0\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection((ip, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(payload)
        chunks = []
        while sum(map(len, chunks)) < 65535:
            try:
                chunk = connection.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            data = b"".join(chunks)
            if b"\r\n\r\n" in data and (b" 401 " in data.splitlines()[0] or b"\nm=" in data):
                break
    return endpoint, b"".join(chunks).decode("utf-8", errors="ignore")


def _digest_authorization(challenge: str, method: str, uri: str, username: str, password: str) -> str:
    values = {}
    for match in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', challenge):
        values[match.group(1).lower()] = match.group(2) or match.group(3) or ""
    realm, nonce = values.get("realm"), values.get("nonce")
    if not realm or not nonce or values.get("algorithm", "MD5").upper() != "MD5":
        return ""
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    qops = {item.strip() for item in values.get("qop", "").lower().split(",")}
    qop = "auth" if "auth" in qops else ""
    if qop:
        nc, cnonce = "00000001", secrets.token_hex(8)
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        suffix = f', qop={qop}, nc={nc}, cnonce="{cnonce}"'
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        suffix = ""
    opaque = f', opaque="{values["opaque"]}"' if values.get("opaque") else ""
    return (
        f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{response}"{opaque}{suffix}'
    )


def _audit_rtsp(
    camera: dict,
    budget: int,
    credentials: tuple[tuple[str, str], ...],
    attempts_by_username: dict[str, int],
    interval: float,
    sleep,
) -> tuple[list, int]:
    ip = camera["ip"]
    attempts = 0
    for port in camera.get("portas_abertas", []):
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if port not in RTSP_PORTS:
            continue
        for path in RTSP_PATHS:
            try:
                endpoint, baseline = _rtsp_request(ip, port, path)
            except OSError:
                continue
            if " 401 " not in (baseline.splitlines()[0] if baseline else ""):
                continue
            challenge_match = re.search(r"WWW-Authenticate:\s*(.+)", baseline, re.I)
            if not challenge_match:
                continue
            challenge = challenge_match.group(1).strip()
            for username, password in credentials:
                if attempts >= budget:
                    return [], attempts
                if not _reserve_attempt(username, attempts_by_username):
                    continue
                if attempts:
                    sleep(interval)
                attempts += 1
                if challenge.lower().startswith("basic"):
                    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
                    authorization = f"Basic {token}"
                else:
                    authorization = _digest_authorization(challenge, "DESCRIBE", endpoint, username, password)
                if not authorization:
                    continue
                try:
                    _, response = _rtsp_request(ip, port, path, authorization)
                except OSError:
                    continue
                status = response.splitlines()[0] if response else ""
                body = response.partition("\r\n\r\n")[2].replace("\r\n", "\n")
                if " 200 " in status and "\nv=0" in "\n" + body and "\nm=" in "\n" + body:
                    return [_finding(ip, "RTSP", endpoint, username)], attempts
    return [], attempts


def audit_default_credentials(
    camera: dict,
    *,
    authorized: bool,
    expanded: bool = False,
    interval: float = 2.0,
    sleep=time.sleep,
    session=None,
) -> list[dict]:
    """Testa uma lista curta somente após autorização explícita e em IPv4 privado."""
    if not authorized:
        raise PermissionError("A auditoria de credenciais exige autorização explícita.")
    if not _private_ip(str(camera.get("ip", ""))):
        raise ValueError("A auditoria de credenciais só pode ser executada em IPv4 privado.")
    interval = max(2.0, float(interval))
    session = session or requests.Session()
    max_attempts = MAX_ATTEMPTS_EXPANDED if expanded else MAX_ATTEMPTS_CONSERVATIVE
    credentials = _credentials_for_camera(camera, expanded)
    attempts_by_username = {}

    findings, attempts, blocked = _audit_http(
        camera,
        max_attempts,
        credentials,
        attempts_by_username,
        interval,
        sleep,
        session,
    )
    if findings or blocked or attempts >= max_attempts:
        return findings
    if attempts:
        sleep(interval)
    rtsp_findings, _ = _audit_rtsp(
        camera,
        max_attempts - attempts,
        credentials,
        attempts_by_username,
        interval,
        sleep,
    )
    return rtsp_findings
