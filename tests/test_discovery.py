import unittest
from unittest.mock import Mock, patch

from modules.discovery import _enriquecer_host, escanear_rede, validar_rede


class DiscoveryTests(unittest.TestCase):
    def test_modo_rapido_nao_executa_segunda_varredura(self):
        dados = {"tcp": {554: {"state": "open"}}}
        with patch("modules.discovery.nmap.PortScanner") as scanner:
            self.assertIs(_enriquecer_host("192.0.2.1", dados, "rapida"), dados)
            scanner.assert_not_called()

    def test_timeout_detalhado_preserva_dados_basicos(self):
        dados = {"tcp": {554: {"state": "open", "name": "rtsp"}}}
        instancia = Mock()
        instancia.all_hosts.return_value = ["192.0.2.1"]
        instancia.__getitem__ = Mock(return_value={"status": {"state": "up"}})
        with patch("modules.discovery.nmap.PortScanner", return_value=instancia):
            resultado = _enriquecer_host("192.0.2.1", dados, "detalhada")
        self.assertEqual(resultado, dados)

    def test_rejeita_profundidade_invalida(self):
        with self.assertRaises(ValueError):
            escanear_rede("192.0.2.0/24", profundidade="invalida")

    def test_rejeita_rede_publica_e_rede_grande(self):
        with self.assertRaises(ValueError):
            validar_rede("8.8.8.0/24")
        with self.assertRaises(ValueError):
            validar_rede("10.0.0.0/8")

    def test_aceita_rede_privada_24(self):
        self.assertEqual(str(validar_rede("192.168.1.33/24")), "192.168.1.0/24")


if __name__ == "__main__":
    unittest.main()
