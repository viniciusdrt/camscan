import streamlit as st
from modules.discovery import escanear_rede
from modules.vulnerability_assessment import nuclei_test
from modules.llm_response import processar_resultados

# Título e descrição da página
st.title("CamScan")
st.write("Escaneie sua rede e descubra se suas câmeras estão seguras.")

# Modo de demonstração
modo_demo = st.checkbox("Usar dados de demonstração (sem câmera real)")

# Campo de texto pra digitar a máscara de rede
mascara = st.text_input("Digite sua máscara de rede:", placeholder="Ex: 192.168.0.0/24")

# Botão pra iniciar o scan
iniciar = st.button("Iniciar Scan")

# Só executa se o usuário clicou no botão e digitou a máscara
if iniciar and mascara:

    if modo_demo:
        resultados = [
            {'ip': '192.168.0.3', 'template_id': 'intelbras-dvr-unauth', 'nome': 'Intelbras DVR - Unrestricted Access', 'severidade': 'low', 'descricao': 'Acesso não autenticado expõe informações sensíveis.', 'encontrado_em': 'http://192.168.0.3:80/cap.js'},
            {'ip': '192.168.0.3', 'template_id': 'intelbras-panel', 'nome': 'Intelbras Router Panel - Detect', 'severidade': 'info', 'descricao': 'Painel administrativo Intelbras detectado.', 'encontrado_em': 'http://192.168.0.3:80'},
            {'ip': '192.168.0.3', 'template_id': 'rtsp-detect', 'nome': 'RTSP - Detect', 'severidade': 'info', 'descricao': 'Stream RTSP detectado e ativo.', 'encontrado_em': '192.168.0.3:554'},
        ]
        with st.spinner("🤖 Gerando relatórios..."):
            relatorios = processar_resultados(resultados)
        st.subheader("📋 Relatórios de Segurança")
        for ip, relatorio in relatorios.items():
            with st.expander(f"📷 Câmera: {ip}"):
                st.markdown(relatorio)

    else:
        # Etapa 1: Descoberta de câmeras
        st.info("🔎 Procurando câmeras na rede...")
        cameras = escanear_rede(mascara)

        if not cameras:
            st.warning("Nenhuma câmera encontrada na rede informada.")

        else:
            st.success(f"✅ {len(cameras)} câmera(s) encontrada(s)!")
            st.info("🔍 Analisando a segurança das câmeras...")
            barra = st.progress(0, text="Iniciando análise...")

            resultados = []
            for i, camera in enumerate(cameras):
                barra.progress(
                    int((i / len(cameras)) * 100),
                    text=f"Analisando câmera {i + 1} de {len(cameras)}: {camera['ip']}"
                )
                resultado_camera = nuclei_test([camera])
                resultados.extend(resultado_camera)

            barra.progress(100, text="Análise concluída!")
            st.success(f"✅ Análise concluída! {len(resultados)} problema(s) encontrado(s).")

            with st.spinner("🤖 Gerando relatórios..."):
                relatorios = processar_resultados(resultados)

            st.subheader("📋 Relatórios de Segurança")
            for ip, relatorio in relatorios.items():
                with st.expander(f"📷 Câmera: {ip}"):
                    st.markdown(relatorio)