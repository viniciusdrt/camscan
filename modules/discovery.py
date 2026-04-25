import json

import nmap
def escanear_rede(ipgeral):
    scanner = nmap.PortScanner()
    dispositivos = scanner.scan(ipgeral, '80,443,554,8080,8554')
    cameras = []
    for ip, dados in dispositivos['scan'].items():
        if dados.get('tcp') and dados['tcp'].get(554) and dados['tcp'][554]['state'] == 'open':
            cameras.append({
                'ip': ip,
                'mac': dados['addresses'].get('mac', ''),
                'fabricante': dados['vendor'].get(dados['addresses'].get('mac', ''), ''),
                'portas_abertas': [
                    porta
                    for porta, info in dados.get('tcp', {}).items()
                    if info.get('state') == 'open'
                ],
                'produto_rtsp': dados['tcp'][554]['product'],
                'versao_rtsp': dados['tcp'][554]['version'],
                })
    return cameras

if __name__ == '__main__':
    mascara = input("Digite sua máscara de rede: ")
    resultado = escanear_rede(mascara)
    print(json.dumps(resultado, indent=2))