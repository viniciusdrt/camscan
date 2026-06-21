import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from modules.default_credentials import (
    MAX_ATTEMPTS_PER_USERNAME,
    _credentials_for_camera,
    audit_default_credentials,
    record_authorization,
)


class DefaultCredentialsTests(unittest.TestCase):
    def test_registra_autorizacao_sem_credenciais(self):
        with tempfile.TemporaryDirectory() as directory:
            target = record_authorization(
                "192.168.1.0/24", [{"ip": "192.168.1.10"}], base_dir=directory
            )
            record = json.loads(target.read_text(encoding="utf-8"))
        self.assertTrue(record["authorization_confirmed"])
        self.assertEqual(["192.168.1.10"], record["targets"])
        self.assertNotIn("credentials", record)

    def test_registra_limite_do_modo_ampliado(self):
        with tempfile.TemporaryDirectory() as directory:
            target = record_authorization(
                "192.168.1.0/24",
                [{"ip": "192.168.1.10"}],
                max_attempts=20,
                base_dir=directory,
            )
            record = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(20, record["max_attempts_per_device"])
        self.assertEqual(5, record["max_attempts_per_username"])

    def test_modo_ampliado_limita_usuario_e_prioriza_fabricante(self):
        credentials = _credentials_for_camera(
            {"fabricante": "Axis Communications", "modelo": "M3045"}, expanded=True
        )
        root_credentials = [item for item in credentials if item[0] == "root"]
        self.assertEqual(("root", "pass"), credentials[0])
        self.assertEqual(20, len(credentials))
        self.assertLessEqual(len(root_credentials), MAX_ATTEMPTS_PER_USERNAME)

    def test_exige_autorizacao_explicita(self):
        with self.assertRaises(PermissionError):
            audit_default_credentials(
                {"ip": "192.168.1.10", "portas_abertas": [80]}, authorized=False
            )

    def test_bloqueia_endereco_publico(self):
        with self.assertRaisesRegex(ValueError, "IPv4 privado"):
            audit_default_credentials(
                {"ip": "8.8.8.8", "portas_abertas": [80]}, authorized=True
            )

    def test_detecta_credencial_http_sem_expor_senha(self):
        session = Mock()
        session.get.side_effect = [
            Mock(status_code=401, headers={"WWW-Authenticate": 'Digest realm="camera"'}),
            Mock(status_code=200, headers={}),
        ]
        camera = {"ip": "192.168.1.10", "portas_abertas": [80]}

        findings = audit_default_credentials(
            camera, authorized=True, sleep=Mock(), session=session
        )

        self.assertEqual("default-credentials-valid", findings[0]["template_id"])
        self.assertNotIn("senha", findings[0])
        self.assertNotIn("admin/admin", str(findings[0]))

    @patch("modules.default_credentials._rtsp_request")
    def test_detecta_credencial_rtsp_com_sdp(self, request):
        request.side_effect = [
            (
                "rtsp://192.168.1.10:554/",
                'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="cam", nonce="abc"\r\n\r\n',
            ),
            (
                "rtsp://192.168.1.10:554/",
                "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nm=video 0 RTP/AVP 96\r\n",
            ),
        ]
        camera = {"ip": "192.168.1.10", "portas_abertas": [554]}

        findings = audit_default_credentials(camera, authorized=True, sleep=Mock())

        self.assertEqual("RTSP", findings[0]["protocolo"])
        self.assertEqual("rtsp://192.168.1.10:554/", findings[0]["encontrado_em"])


if __name__ == "__main__":
    unittest.main()
