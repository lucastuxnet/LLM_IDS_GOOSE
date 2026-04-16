def rule_random_replay_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto nos valores de StNum, indicando uma variação anormal.
    
    A regra é baseada na comparação do desvio padrão dos valores de StNum com o dobro do desvio padrão normal.
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', 199.2918) if baseline else 199.2918
    LIMIAR = DESVIO_ST_NORMAL * 2
    stnum_desvio_padrão = packet.get('stDiff', 0)
    if stnum_desvio_padrão > LIMIAR:
        return True
    return False


def rule_random_replay_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto nos valores de SqNum, indicando uma variação anormal.
    
    A regra é baseada na comparação do desvio padrão dos valores de SqNum com o dobro do desvio padrão normal.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000) if baseline else 6.0000
    LIMIAR = INCREMENTO_SQ_NORMAL * 3
    sqnum_desvio_padrão = packet.get('sqDiff', 0)
    if sqnum_desvio_padrão > LIMIAR:
        return True
    return False


def rule_random_replay_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto nos intervalos de tempo, indicando uma variação anormal.
    
    A regra é baseada na comparação do desvio padrão dos intervalos de tempo com o triplo do desvio padrão normal.
    """
    TIMESTAMP_DESVIO = baseline.get('TIMESTAMP_DESVIO', 0.116331) if baseline else 0.116331
    LIMIAR = TIMESTAMP_DESVIO * 3
    timestamp_desvio_padrão = packet.get('timestampDiff', 0)
    if timestamp_desvio_padrão > LIMIAR:
        return True
    return False


def rule_random_replay_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento anormal nos valores de StNum, indicando uma variação anormal.
    
    A regra é baseada na comparação do incremento dos valores de StNum com o triplo do incremento normal.
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', 180.0000) if baseline else 180.0000
    LIMIAR = INCREMENTO_ST_NORMAL * 3
    stnum_incremento = packet.get('stDiff', 0)
    if stnum_incremento > LIMIAR or stnum_incremento < -LIMIAR:
        return True
    return False


def rule_random_replay_cbstatus_inconsistente(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta inconsistência nos valores de cbStatus, indicando uma possível manipulação dos dados.
    
    A regra é baseada na comparação do valor de cbStatus com o valor esperado.
    """
    cbstatus_esperado = baseline.get('cbStatus', 0) if baseline else 0
    cbstatus_atual = packet.get('cbStatus', 0)
    if cbstatus_atual != cbstatus_esperado:
        return True
    return False