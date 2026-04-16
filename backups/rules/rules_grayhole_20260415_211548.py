def rule_grayhole_stnum_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão de StNum com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('StNum', {}).get('max_normal', DESVIO_ST_NORMAL) * 3 if baseline else DESVIO_ST_NORMAL * 3
    valor = packet.get('stDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_sqnum_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão de SqNum com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('SqNum', {}).get('max_normal', 10) * 2 if baseline else 20
    valor = packet.get('sqDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_stnum_crescimento_rapido(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento de StNum mais rápido do que o esperado.
    
    A regra é baseada na comparação do crescimento de StNum com o valor máximo normal.
    Se o crescimento for maior que 2 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('StNum', {}).get('max_normal', INCREMENTO_ST_NORMAL) * 2 if baseline else INCREMENTO_ST_NORMAL * 2
    valor = packet.get('stDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_timestamp_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo de chegada dos pacotes significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do tempo de chegada com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('timestamp', {}).get('max_normal', TIMESTAMP_DESVIO) * 3 if baseline else TIMESTAMP_DESVIO * 3
    valor = packet.get('timestampDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_t_diff_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo de diferença entre os pacotes significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do tempo de diferença com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('tDiff', {}).get('max_normal', 10) * 2 if baseline else 20
    valor = packet.get('tDiff', 0)
    if valor > LIMIAR:
        return True
    return False