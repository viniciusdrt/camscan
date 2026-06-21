import os
import unittest
from unittest.mock import Mock, patch

from modules.public_exposure import verificar_exposicao_publica


class PublicExposureTests(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=False)
    def test_sem_sonda_retorna_inconclusivo(self):
        os.environ.pop("EXTERNAL_PORT_CHECK_URL", None)
        resultado = verificar_exposicao_publica("203.0.113.10")
        self.assertEqual(resultado["status"], "inconclusivo")
        self.assertEqual(resultado["achados"], [])

    @patch.dict(os.environ, {"EXTERNAL_PORT_CHECK_URL": "https://probe.example/check"})
    def test_sonda_externa_registra_porta_aberta(self):
        resposta = Mock()
        resposta.raise_for_status.return_value = None
        resposta.json.return_value = {"open": True}
        session = Mock()
        session.get.return_value = resposta
        resultado = verificar_exposicao_publica("203.0.113.10", session=session)
        self.assertEqual(resultado["status"], "ok")
        self.assertEqual(len(resultado["achados"]), 7)
        self.assertIn("encontrado_em", resultado["achados"][0])


if __name__ == "__main__":
    unittest.main()
