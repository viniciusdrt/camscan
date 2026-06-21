import unittest
from unittest.mock import patch

from modules.llm_response import processar_resultados


class LlmResponseTests(unittest.TestCase):
    def test_relatorio_geral_envia_apenas_quantidade_de_cves(self):
        resultados = [
            {
                "ip": "192.0.2.1",
                "template_id": "CVE-2025-0001",
                "nome": "CVE-2025-0001",
                "severidade": "critical",
                "descricao": "Descrição técnica que não deve aparecer.",
            },
            {
                "ip": "192.0.2.1",
                "template_id": "CVE-2025-0002",
                "nome": "CVE-2025-0002",
                "severidade": "high",
                "descricao": "Outra descrição técnica.",
            },
        ]
        mensagens = []
        with patch("modules.llm_response.resposta_chatbot", side_effect=lambda texto: mensagens.append(texto) or "Relatório simples"):
            relatorios = processar_resultados(resultados, usar_ia=True)

        self.assertEqual(relatorios["192.0.2.1"], "Relatório simples")
        self.assertIn("2 CVE(s)", mensagens[0])
        self.assertNotIn("CVE-2025-0001", mensagens[0])
        self.assertNotIn("Descrição técnica", mensagens[0])

    def test_relatorio_local_nao_chama_groq(self):
        with patch("modules.llm_response.resposta_chatbot") as chatbot:
            relatorios = processar_resultados([], cameras=[{"ip": "192.0.2.1"}], usar_ia=False)
        chatbot.assert_not_called()
        self.assertIn("sem enviar dados", relatorios["192.0.2.1"])


if __name__ == "__main__":
    unittest.main()
