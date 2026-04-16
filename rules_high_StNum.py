def rule_high_StNum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior que o desvio padrão médio.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o desvio padrão for anormal, False caso contrário
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', DESVIO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_high_StNum_crescimento_exponencial(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento exponencial de StNum em relação ao crescimento médio.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o crescimento for exponencial, False caso contrário
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', INCREMENTO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 5:
        return True
    return False


def rule_high_StNum_crescimento_acelerado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento acelerado de StNum em relação ao crescimento médio.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o crescimento for acelerado, False caso contrário
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', INCREMENTO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 4:
        return True
    return False


def rule_high_StNum_desvio_medio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio médio de StNum significativamente maior que o desvio médio esperado.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o desvio médio for anormal, False caso contrário
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', DESVIO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 2.5:
        return True
    return False