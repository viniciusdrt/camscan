import unittest

from modules.cve_report import montar_dados_para_ia, montar_detalhes_tecnicos


class CveReportTests(unittest.TestCase):
    def setUp(self):
        self.camera = {"ip": "192.0.2.1", "fabricante": "Intelbras", "modelo": "ABC-123"}
        self.cves = [{
            "template_id": "CVE-2025-0001",
            "cvss": 9.8,
            "severidade": "critical",
            "descricao": "Example vulnerability.",
            "termo_busca": "Intelbras ABC-123",
            "correspondencias": ["intelbras", "abc-123"],
            "encontrado_em": "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
        }]

    def test_prompt_contem_identificacao_e_cve(self):
        texto = montar_dados_para_ia(self.camera, self.cves)
        self.assertIn("Intelbras | ABC-123", texto)
        self.assertIn("CVE-2025-0001", texto)

    def test_detalhes_tecnicos_preservam_fonte_e_cvss(self):
        texto = montar_detalhes_tecnicos(self.cves)
        self.assertIn("9.8", texto)
        self.assertIn("CVE-2025-0001", texto)
        self.assertIn(self.cves[0]["encontrado_em"], texto)


if __name__ == "__main__":
    unittest.main()
