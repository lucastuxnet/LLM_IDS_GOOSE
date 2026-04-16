def rule_inverse_replay_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo StNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do campo StNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    DESVIO_ST_NORMAL = baseline.get('StNum', {}).get('desvio_padrao', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_inverse_replay_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo SqNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do campo SqNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('SqNum', {}).get('incremento_normal', INCREMENTO_SQ_NORMAL) if baseline else INCREMENTO_SQ_NORMAL
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > INCREMENTO_SQ_NORMAL * 3:
        return True
    return False


def rule_inverse_replay_cbstatus_comportamento_anômalo(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta comportamento anômalo do campo cbStatus.
    
    A regra é baseada na comparação da frequência de mudanças do campo cbStatus com o valor esperado.
    Se a frequência de mudanças for maior que 2 vezes o valor esperado, a regra é acionada.
    """
    cb_status_diff = packet.get('cbStatusDiff', 0)
    if cb_status_diff > 2:
        return True
    return False


def rule_inverse_replay_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo timestampDiff significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do campo timestampDiff com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    TIMESTAMP_DESVIO = baseline.get('timestampDiff', {}).get('desvio_padrao', TIMESTAMP_DESVIO) if baseline else TIMESTAMP_DESVIO
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 3:
        return True
    return False


def rule_inverse_replay_stnum_incremento_anômalo(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento anômalo do campo StNum.
    
    A regra é baseada na comparação do incremento do campo StNum com o valor esperado.
    Se o incremento for maior que 2 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_ST_NORMAL = baseline.get('StNum', {}).get('incremento_normal', INCREMENTO_ST_NORMAL) if baseline else INCREMENTO_ST_NORMAL
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 2:
        return True
    return False