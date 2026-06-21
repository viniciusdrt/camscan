import streamlit as st
from modules.discovery import escanear_rede
from modules.vulnerability_assessment import avaliar_vulnerabilidades
from modules.llm_response import processar_resultados
from modules.public_exposure import verificar_exposicao_publica, descobre_ip_publico
from modules.cve_lookup import consultar_cves
from modules.cve_report import gerar_explicacao_cves, montar_detalhes_tecnicos
from modules.default_credentials import audit_default_credentials, record_authorization

st.title("CamScan")
st.write("Escaneie sua rede e descubra se suas câmeras estão seguras.")

usar_ia = st.checkbox(
    "Usar IA para explicar os resultados",
    value=False,
    help=(
        "Quando ativado, IP local, identificação do equipamento e achados são enviados à API da Groq. "
        "Desativado, o relatório é gerado localmente."
    ),
)

st.subheader("1. Escolha o alcance")
modo = st.radio(
    "Onde deseja verificar?",
    ["Apenas rede local", "Rede local + exposição pública"],
    key="alcance_scan",
)
st.subheader("2. Escolha a profundidade")
tipo_varredura = st.radio(
    "Profundidade da varredura:",
    ["Varredura completa rápida", "Varredura detalhada"],
    key="profundidade_scan",
    help=(
        "A rápida prioriza velocidade e pode localizar CVEs apenas pelo fabricante. "
        "A detalhada tenta identificar serviços, modelo e firmware para aumentar a precisão."
    ),
)
if tipo_varredura == "Varredura completa rápida":
    st.caption("⚡ Mais rápida: detecta portas e fabricante, mas pode produzir CVEs menos específicos.")
    profundidade = "rapida"
else:
    st.caption("🔬 Mais longa: usa Nmap, ONVIF, SSDP, mDNS, HTTP e RTSP para tentar identificar modelo e firmware.")
    profundidade = "detalhada"

st.subheader("3. Auditoria opcional de credenciais padrão")
auditar_credenciais = st.checkbox(
    "Testar uma lista curta de credenciais padrão",
    value=False,
    help="Oferece um modo conservador de 10 tentativas e um modo ampliado de 20.",
)
autorizacao_valida = False
auditoria_ampliada = False
maximo_tentativas_credenciais = 10
if auditar_credenciais:
    modo_auditoria_credenciais = st.radio(
        "Intensidade da auditoria:",
        ["Conservadora — até 10 tentativas", "Ampliada — até 20 tentativas"],
        horizontal=True,
        key="modo_auditoria_credenciais",
    )
    auditoria_ampliada = modo_auditoria_credenciais.startswith("Ampliada")
    maximo_tentativas_credenciais = 20 if auditoria_ampliada else 10
    st.warning(
        "O teste realizará autenticações reais e pode gerar alertas ou bloqueio temporário. "
        "Ele não usa wordlists nem executa tentativas em endereços públicos."
    )
    confirma_autorizacao = st.checkbox(
        "Sou proprietário ou tenho autorização para testar os dispositivos desta rede.",
        key="confirma_autorizacao_credenciais",
    )
    confirma_risco = st.checkbox(
        "Entendo o risco de bloqueio ou indisponibilidade temporária.",
        key="confirma_risco_credenciais",
    )
    confirma_ampliado = True
    if auditoria_ampliada:
        st.warning(
            "O modo ampliado testa até 20 combinações, prioriza credenciais relacionadas ao "
            "fabricante identificado e limita cada usuário a cinco tentativas."
        )
        confirma_ampliado = st.checkbox(
            "Autorizo especificamente o modo ampliado de até 20 tentativas por dispositivo.",
            key="confirma_modo_ampliado",
        )
    frase_esperada = "AUTORIZO TESTE AMPLIADO" if auditoria_ampliada else "AUTORIZO O TESTE"
    frase_autorizacao = st.text_input(
        f"Digite {frase_esperada} para confirmar:",
        key="frase_autorizacao_credenciais",
    )
    autorizacao_valida = (
        confirma_autorizacao
        and confirma_risco
        and confirma_ampliado
        and frase_autorizacao.strip() == frase_esperada
    )

mascara = st.text_input("Digite sua máscara de rede:", placeholder="Ex: 192.168.0.0/24")
iniciar = st.button("Iniciar Scan")

if iniciar and mascara:

    if auditar_credenciais and not autorizacao_valida:
        st.error("A auditoria de credenciais não foi iniciada porque a autorização está incompleta.")
        st.stop()

    st.info(f"Configuração selecionada: **{modo}** · **{tipo_varredura}**")
    st.info("🔎 Procurando câmeras na rede...")
    try:
        cameras = escanear_rede(mascara, profundidade=profundidade)
    except (ValueError, OSError) as erro:
        st.error(str(erro))
        st.stop()

    if not cameras:
        st.warning("Nenhuma câmera encontrada na rede informada.")

    else:
        st.success(f"✅ {len(cameras)} câmera(s) encontrada(s)!")
        if auditar_credenciais:
            try:
                record_authorization(
                    mascara,
                    cameras,
                    max_attempts=maximo_tentativas_credenciais,
                )
            except OSError as erro:
                st.error(f"Não foi possível registrar a autorização da auditoria: {erro}")
                st.stop()
        st.info("🔍 Analisando a segurança das câmeras...")
        barra = st.progress(0, text="Iniciando análise...")

        resultados = []
        cves_por_ip = {}
        for i, camera in enumerate(cameras):
            barra.progress(
                int((i / len(cameras)) * 100),
                text=f"Analisando câmera {i + 1} de {len(cameras)}: {camera['ip']}"
            )
            identificacao = " | ".join(filter(None, [
                camera.get("fabricante"), camera.get("modelo"), camera.get("produto_rtsp"),
                camera.get("versao_rtsp"), ", ".join(camera.get("produtos_detectados", [])),
            ]))
            st.caption(f"Identificação detectada: {identificacao or 'não identificada'}")
            if camera.get("enumeracao"):
                with st.expander(f"Fontes de identificação de {camera['ip']}"):
                    st.json(camera["enumeracao"], expanded=False)
            try:
                resultado_camera = avaliar_vulnerabilidades([camera])
                resultados.extend(resultado_camera)
            except (OSError, RuntimeError) as erro:
                st.error(f"Falha ao executar o Nuclei em {camera['ip']}: {erro}")

            if auditar_credenciais:
                st.info(f"🔐 Testando credenciais padrão autorizadas em {camera['ip']}...")
                try:
                    achados_credenciais = audit_default_credentials(
                        camera,
                        authorized=True,
                        expanded=auditoria_ampliada,
                    )
                    resultados.extend(achados_credenciais)
                    if achados_credenciais:
                        st.error(f"Credencial padrão aceita por {camera['ip']}. Altere-a imediatamente.")
                    else:
                        st.success(f"Nenhuma credencial padrão testada foi aceita por {camera['ip']}.")
                except (PermissionError, ValueError, OSError) as erro:
                    st.warning(f"Auditoria de credenciais não concluída em {camera['ip']}: {erro}")

            st.info(f"🔎 Buscando CVEs conhecidos para {camera['ip']}...")
            consulta = consultar_cves(camera)
            cves = consulta["achados"]
            cves_por_ip[camera["ip"]] = cves
            if cves:
                st.warning(f"⚠️ {len(cves)} CVE(s) potencialmente relacionado(s) a {camera['ip']}. Confirme modelo e firmware antes de concluir que a câmera é afetada.")
            elif consulta["status"] in {"sem_identificacao", "identificacao_insuficiente"}:
                st.warning(
                    "CVEs não foram consultados porque o modelo exato da câmera não foi identificado. "
                    "A busca somente por fabricante foi bloqueada para evitar falsos positivos."
                )
            elif consulta["status"] == "erro":
                st.error("A consulta à base NVD falhou; isso não significa que não existam CVEs.")
            else:
                st.success(f"✅ Nenhum CVE relacionado foi localizado para {camera['ip']} com os dados identificados.")
            if consulta["erros"]:
                with st.expander("Detalhes da consulta de CVEs"):
                    st.code("\n".join(consulta["erros"]))
            if consulta.get("cache_utilizado"):
                st.caption("Resultado de CVEs carregado do cache local da última consulta bem-sucedida à NVD.")
            resultados.extend(cves)

        barra.progress(100, text="Análise concluída!")

        if modo == "Rede local + exposição pública":
            st.info("🌐 Verificando exposição pública...")
            ip_publico = descobre_ip_publico()
            if ip_publico:
                st.info(f"IP público detectado: {ip_publico}")
                exposicao = verificar_exposicao_publica(ip_publico)
                achados_publicos = exposicao["achados"]
                if exposicao["status"] == "inconclusivo":
                    st.warning(exposicao["mensagem"])
                elif achados_publicos:
                    st.error(f"⚠️ {len(achados_publicos)} porta(s) responderam à sonda externa!")
                else:
                    st.success("✅ A sonda externa não encontrou as portas verificadas abertas.")
                if exposicao["erros"]:
                    with st.expander("Erros da verificação externa"):
                        st.code("\n".join(exposicao["erros"]))
            else:
                st.error("Não foi possível descobrir o IP público.")

        st.success(f"✅ Análise concluída! {len(resultados)} problema(s) encontrado(s).")

        with st.spinner("🤖 Gerando relatórios..."):
            relatorios = processar_resultados(resultados, cameras=cameras, usar_ia=usar_ia)

        st.subheader("📋 Relatórios de Segurança")
        for ip, relatorio in relatorios.items():
            with st.expander(f"📷 Câmera: {ip}"):
                st.markdown(relatorio)

        cameras_com_cves = [camera for camera in cameras if cves_por_ip.get(camera["ip"])]
        if cameras_com_cves:
            st.subheader("🔎 Detalhes das CVEs encontradas")
            st.caption(
                "As explicações ajudam na análise, mas a confirmação exige comparar o modelo e o firmware exatos com o registro da NVD."
            )
            for camera in cameras_com_cves:
                ip = camera["ip"]
                cves = cves_por_ip[ip]
                with st.expander(f"🛡️ {ip}: {len(cves)} CVE(s) potencialmente relacionada(s)"):
                    with st.spinner(f"Gerando explicações das CVEs de {ip}..."):
                        explicacao = gerar_explicacao_cves(camera, cves, usar_ia=usar_ia)
                    st.markdown("### Explicação em linguagem simples")
                    st.markdown(explicacao)
                    st.markdown(montar_detalhes_tecnicos(cves))
