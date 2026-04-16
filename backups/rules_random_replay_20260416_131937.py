def rule_random_replay_stnum_desvio_elevado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior do que o esperado.
    
    A regra verifica se o desvio padrão de StNum é maior que 3 vezes o desvio padrão normal.
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', 199.2918) if baseline else 199.2918
    stnum_desvio = packet.get('stDiff', 0)
    if stnum_desvio > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_random_replay_sqnum_desvio_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum anormalmente alto.
    
    A regra verifica se o desvio padrão de SqNum é maior que 2 vezes o incremento normal de SqNum.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000) if baseline else 6.0000
    sqnum_desvio = packet.get('sqDiff', 0)
    if sqnum_desvio > INCREMENTO_SQ_NORMAL * 2:
        return True
    return False


def rule_random_replay_timestamp_diff_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo entre pacotes significativamente diferente do esperado.
    
    A regra verifica se o desvio padrão do tempo entre pacotes é maior que 2 vezes o desvio padrão normal do tempo.
    """
    TIMESTAMP_DESVIO = baseline.get('TIMESTAMP_DESVIO', 0.116331) if baseline else 0.116331
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 2:
        return True
    return False


def rule_random_replay_goose_length_diff_zero(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta diferença de comprimento do pacote GOOSE consistentemente zero.
    
    A regra verifica se a diferença de comprimento do pacote GOOSE é zero e se o pacote não é o primeiro.
    """
    goose_length_diff = packet.get('gooseLengthDiff', 0)
    if goose_length_diff == 0 and packet.get('packet_id', 0) > 0:
        return True
    return False


def rule_random_replay_apdu_size_diff_zero(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta diferença de tamanho do APDU consistentemente zero.
    
    A regra verifica se a diferença de tamanho do APDU é zero e se o pacote não é o primeiro.
    """
    apdu_size_diff = packet.get('apduSizeDiff', 0)
    if apdu_size_diff == 0 and packet.get('packet_id', 0) > 0:
        return True
    return False