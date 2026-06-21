import unittest

from modules.device_enumeration import _autorizacao_digest, _extrair_identidade


class DeviceEnumerationTests(unittest.TestCase):
    def test_extrai_modelo_e_firmware(self):
        identidade = _extrair_identidade(['Model: VIP-3230-B firmware="3.2.5"'])
        self.assertEqual(identidade["modelo"], "VIP-3230-B")
        self.assertEqual(identidade["firmware"], "3.2.5")

    def test_monta_digest_rtsp_sem_expor_senha(self):
        cabecalho = _autorizacao_digest(
            'Digest realm="camera", nonce="abc123"',
            "DESCRIBE",
            "rtsp://192.0.2.1:554/",
            "admin",
            "senha-secreta",
        )
        self.assertIn('username="admin"', cabecalho)
        self.assertIn('response="', cabecalho)
        self.assertNotIn("senha-secreta", cabecalho)


if __name__ == "__main__":
    unittest.main()
