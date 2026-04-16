def rule_grayhole_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo StNum, indicando variação anormal no número de sequência.
    
    A regra é baseada na comparação do desvio padrão do campo StNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    DESVIO_ST_NORMAL = baseline.get('StNum', {}).get('desvio_padrao', DESVIO_ST_NORMAL)
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False

def rule_grayhole_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo SqNum, indicando variação anormal no número de sequência.
    
    A regra é baseada na comparação do desvio padrão do campo SqNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('SqNum', {}).get('incremento_normal', INCREMENTO_SQ_NORMAL)
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > INCREMENTO_SQ_NORMAL * 3:
        return True
    return False

def rule_grayhole_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo timestampDiff, indicando variação anormal no tempo de chegada dos pacotes.
    
    A regra é baseada na comparação do desvio padrão do campo timestampDiff com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    TIMESTAMP_DESVIO = baseline.get('timestampDiff', {}).get('desvio_padrao', TIMESTAMP_DESVIO)
    valor = packet.get('timestampDiff', 0)
    if valor > TIMESTAMP_DESVIO * 3:
        return True
    return False

def rule_grayhole_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento anormal no campo StNum, indicando anormalidade no número de sequência.
    
    A regra é baseada na comparação do incremento do campo StNum com o valor esperado.
    Se o incremento for maior ou menor que 3 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_ST_NORMAL = baseline.get('StNum', {}).get('incremento_normal', INCREMENTO_ST_NORMAL)
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 3 or st_diff < INCREMENTO_ST_NORMAL / 3:
        return True
    return False

def rule_grayhole_cbstatus_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo cbStatus, indicando variação anormal no status do controle de bloqueio.
    
    A regra é baseada na comparação do desvio padrão do campo cbStatus com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    valor = packet.get('cbStatus', 0)
    cb_status_diff = packet.get('cbStatusDiff', 0)
    if cb_status_diff > 3:
        return True
    return False