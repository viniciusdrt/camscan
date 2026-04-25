from discovery import escanear_rede
import subprocess
import os


def nuclei_test (cameras):
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    NUCLEI_PATH = os.path.join(BASE_DIR, 'nuclei.exe')
    resultados = []
    for camera in cameras:
        resultado = subprocess.run(
            [NUCLEI_PATH, '-u', f"http://{camera['ip']}:80", '-jsonl'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace')
        resultados.append(f"camera_{camera['ip']}: {resultado}")
    return resultados

if __name__ == '__main__':
    mascara = input("Digite sua máscara de rede: ")
    cameras = escanear_rede(mascara)
    resultados = nuclei_test(cameras)
    for r in resultados:
        print(r)