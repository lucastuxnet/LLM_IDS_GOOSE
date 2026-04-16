def rule_masquerade_fake_normal_stnum_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão de StNum for anormal, False caso contrário.
    """
    DESVIO_ST_NORMAL = baseline.get('stnum', {}).get('desvio_padrao', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_sqnum_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão de SqNum for anormal, False caso contrário.
    """
    DESVIO_SQ_NORMAL = baseline.get('sqnum', {}).get('desvio_padrao', 10) if baseline else 10
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > DESVIO_SQ_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento de StNum significativamente maior ou menor que o incremento típico.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o incremento de StNum for anormal, False caso contrário.
    """
    INCREMENTO_ST_NORMAL = baseline.get('stnum', {}).get('incremento', INCREMENTO_ST_NORMAL) if baseline else INCREMENTO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 3 or st_diff < -INCREMENTO_ST_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_timestamp_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo de chegada dos pacotes significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão do tempo de chegada for anormal, False caso contrário.
    """
    TIMESTAMP_DESVIO = baseline.get('timestamp', {}).get('desvio_padrao', TIMESTAMP_DESVIO) if baseline else TIMESTAMP_DESVIO
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 3:
        return True
    return False


def rule_masquerade_fake_normal_goose_length_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tamanho do pacote GOOSE significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão do tamanho do pacote GOOSE for anormal, False caso contrário.
    """
    GOOSE_LENGTH_DESVIO = baseline.get('goose', {}).get('desvio_padrao', 10) if baseline else 10
    goose_length_diff = packet.get('gooseLengthDiff', 0)
    if goose_length_diff > GOOSE_LENGTH_DESVIO * 3:
        return True
    return False