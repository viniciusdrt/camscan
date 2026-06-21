import unittest
from unittest.mock import Mock

import requests

from modules.cve_lookup import _termos_busca, consultar_cves


class CveLookupTests(unittest.TestCase):
    def test_extrai_cvss_remove_duplicata_e_filtra_irrelevante(self):
        resposta = Mock()
        resposta.raise_for_status.return_value = None
        resposta.json.return_value = {
            "vulnerabilities": [
                {"cve": {
                    "id": "CVE-2025-0001",
                    "descriptions": [{"lang": "en", "value": "Intelbras camera model XYZ is vulnerable."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                }},
                {"cve": {
                    "id": "CVE-2025-0002",
                    "descriptions": [{"lang": "en", "value": "Unrelated database product."}],
                }},
            ]
        }
        session = Mock()
        session.get.return_value = resposta
        resultado = consultar_cves(
            {"ip": "192.0.2.1", "fabricante": "Intelbras", "modelo": "XYZ"},
            session=session,
        )

        self.assertEqual(resultado["status"], "ok")
        self.assertEqual([a["template_id"] for a in resultado["achados"]], ["CVE-2025-0001"])
        self.assertEqual(resultado["achados"][0]["severidade"], "critical")
        self.assertEqual(resultado["achados"][0]["cvss"], 9.8)
        self.assertFalse(resultado["achados"][0]["confirmado"])

    def test_distingue_erro_da_api_de_resultado_vazio(self):
        session = Mock()
        session.get.side_effect = requests.Timeout("tempo esgotado")
        resultado = consultar_cves(
            {"ip": "192.0.2.1", "fabricante": "Intelbras", "modelo": "XYZ"},
            session=session,
        )
        self.assertEqual(resultado["status"], "erro")
        self.assertTrue(resultado["erros"])

    def test_requer_identificacao(self):
        resultado = consultar_cves({"ip": "192.0.2.1"})
        self.assertEqual(resultado["status"], "identificacao_insuficiente")
        self.assertEqual(resultado["achados"], [])

    def test_bloqueia_busca_apenas_por_fabricante(self):
        session = Mock()
        resultado = consultar_cves(
            {"ip": "192.0.2.1", "fabricante": "Intelbras"}, session=session
        )
        self.assertEqual(resultado["status"], "identificacao_insuficiente")
        session.get.assert_not_called()

    def test_banner_generico_nao_cria_consulta_instavel(self):
        termos = _termos_busca({
            "fabricante": "Intelbras",
            "produtos_detectados": ["Intelbras webcam httpd"],
        })
        self.assertEqual(termos, ["Intelbras"])

    def test_modelo_especifico_remove_cve_de_outro_produto(self):
        resposta = Mock()
        resposta.status_code = 200
        resposta.headers = {}
        resposta.raise_for_status.return_value = None
        resposta.json.return_value = {"vulnerabilities": [{"cve": {
            "id": "CVE-2025-9999",
            "descriptions": [{"lang": "en", "value": "Intelbras WRN 150 router vulnerability."}],
        }}]}
        session = Mock()
        session.get.return_value = resposta
        resultado = consultar_cves(
            {"ip": "192.0.2.1", "fabricante": "Intelbras", "modelo": "VIP-3230-B"},
            session=session,
        )
        self.assertEqual(resultado["achados"], [])


if __name__ == "__main__":
    unittest.main()
