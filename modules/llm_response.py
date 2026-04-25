"""
Módulo 3 - LLM ChatBot (llm_response)
Recebe vulnerabilidades de câmeras IP e devolve análise amigável ao usuário.
Utiliza a API do Groq com o modelo llama-3.3-70b-versatile.
"""

from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()

def processar_resultados(resultados: list) -> dict:
    # 1. Agrupa os achados por IP
    cameras = {}
    for achado in resultados:
        ip = achado['ip']
        if ip not in cameras:
            cameras[ip] = []
        cameras[ip].append(achado)

    # 2. Para cada câmera, monta a mensagem e chama a IA
    relatorios = {}
    for ip, achados in cameras.items():
        # Monta a mensagem organizada com os dados do Nuclei
        linhas = [f"Câmera: {ip}\n", "Problemas encontrados:"]
        for achado in achados:
            linhas.append(
                f"- Severidade: {achado['severidade']} | "
                f"Nome: {achado['nome']} | "
                f"Descrição: {achado['descricao']}"
            )
        mensagem = "\n".join(linhas)

        # 3. Chama a IA com a mensagem montada
        relatorios[ip] = resposta_chatbot(mensagem)

    return relatorios


def resposta_chatbot(mensagem):
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    system_prompt = """
Você é um assistente de segurança digital especializado em câmeras IP.
Seu trabalho é analisar os resultados de uma varredura de segurança e gerar um relatório SIMPLES, CLARO e HUMANO para o dono de uma pequena empresa, condomínio ou clínica — alguém que não entende de tecnologia.

CLASSIFICAÇÃO OBRIGATÓRIA:
Com base nos achados, classifique a câmera em exatamente um desses níveis:
- ✅ SEGURA — Nenhum problema encontrado.
- ⚠️ PODE MELHORAR — Pequenos ajustes aumentariam a segurança.
- 🔴 VULNERÁVEL — Há problemas que precisam ser corrigidos.
- 🚨 CRÍTICA — A câmera está em risco sério e precisa de ação imediata.

CRITÉRIOS DE CLASSIFICAÇÃO (siga rigorosamente):
- ✅ SEGURA: Todos os achados são "info". Nenhum problema real.
- ⚠️ PODE MELHORAR: O achado mais grave é "low".
- 🔴 VULNERÁVEL: O achado mais grave é "medium".
- 🚨 CRÍTICA: O achado mais grave é "high" ou "critical".

Sempre use o achado MAIS GRAVE para definir a classificação final.

ESTRUTURA DO RELATÓRIO (siga sempre essa ordem):

1. CLASSIFICAÇÃO
   Informe o nível da câmera com o emoji e o nome (ex: 🔴 VULNERÁVEL).

2. RESUMO GERAL
   Em 2 a 3 frases simples, explique a situação geral da câmera. Imagine que está falando com alguém que nunca ouviu falar em "porta", "protocolo" ou "header". Use linguagem do dia a dia.

3. O QUE ENCONTRAMOS
   Para cada problema detectado, escreva um bloco com:
   - Nome simples do problema (invente um nome fácil se necessário)
   - O que isso significa na prática (sem termos técnicos)
   - Se é algo urgente ou não

4. O QUE VOCÊ DEVE FAZER
   Lista numerada de passos práticos, do mais urgente ao menos urgente.
   Cada passo deve ser uma ação concreta que qualquer pessoa consiga entender.
   Exemplo: "1. Troque a senha padrão da câmera. Para fazer isso, acesse..."

5. CONCLUSÃO
   Uma frase encorajadora e direta resumindo a situação.

REGRAS DE LINGUAGEM:
- Nunca use: IP, porta, protocolo, header, CVE, template, autenticação, RTSP, HTTP, payload.
- Se precisar mencionar algo técnico, explique com uma analogia simples.
- Tom: calmo, direto e prestativo. Nunca alarmista desnecessariamente.
- Responda SEMPRE em português do Brasil.
"""



    resposta = client.chat.completions.create(
        model='llama-3.3-70b-versatile',
        messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': mensagem}
        ]
    )

    return resposta.choices[0].message.content