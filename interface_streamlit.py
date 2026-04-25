import streamlit as st
from modules.discovery import escanear_rede
from modules.vulnerability_assessment import nuclei_test
from modules.llm_response import processar_resultados

# Título e descrição da página
st.title("CamScan")
st.write("Escaneie sua rede e descubra se suas câmeras estão seguras.")

# Campo de texto pra digitar a máscara de rede
mascara = st.text_input("Digite sua máscara de rede:", placeholder="Ex: 267.067.6.0/24")

# Botão pra iniciar o scan
iniciar = st.button("Iniciar Scan")

# Só executa se o usuário clicou no botão e digitou a máscara
if iniciar and mascara:

    # Etapa 1: Descoberta de câmeras
    st.info("🔎 Procurando câmeras na rede...")
    cameras = escanear_rede(mascara)

    # Se não encontrou nenhuma câmera, avisa o usuário e para por aqui
    if not cameras:
        st.warning("Nenhuma câmera encontrada na rede informada.")

    # Se encontrou, mostra quantas achou e continua
    else:
        st.success(f"✅ {len(cameras)} câmera(s) encontrada(s)!")
        # Etapa 2: Análise de vulnerabilidades
        st.info("🔍 Analisando a segurança das câmeras...")
        barra = st.progress(0, text="Iniciando análise...")

        resultados = []
        for i, camera in enumerate(cameras):
            # Atualiza o status e a barra pra cada câmera
            barra.progress(
                int((i / len(cameras)) * 100),
                text=f"Analisando câmera {i + 1} de {len(cameras)}: {camera['ip']}"
            )
            # Roda o Nuclei só nessa câmera
            resultado_camera = nuclei_test([camera])
            resultados.extend(resultado_camera)

        # Barra 100% ao terminar
        barra.progress(100, text="Análise concluída!")
        st.success(f"✅ Análise concluída! {len(resultados)} problema(s) encontrado(s).")

        # Etapa 3: Geração dos relatórios pela IA
        with st.spinner("🤖 Gerando relatórios..."):
            relatorios = processar_resultados(resultados)

        # Exibe o relatório de cada câmera
        st.subheader("📋 Relatórios de Segurança")
        for ip, relatorio in relatorios.items():
            with st.expander(f"📷 Câmera: {ip}"):
                st.markdown(relatorio)