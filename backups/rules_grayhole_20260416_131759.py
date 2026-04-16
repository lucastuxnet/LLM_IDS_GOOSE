def rule_grayhole_stnum_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior do que o esperado,
    indicando uma variação anormal nos valores de StNum.
    """
    DESVIO_NORMAL = baseline.get('StNum', {}).get('desvio_normal', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_NORMAL * 3:
        return True
    return False

def rule_grayhole_sqnum_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum maior do que o esperado,
    sugerindo uma variação anormal nos valores de SqNum.
    """
    INCREMENTO_NORMAL = baseline.get('SqNum', {}).get('incremento_normal', INCREMENTO_SQ_NORMAL) if baseline else INCREMENTO_SQ_NORMAL
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > INCREMENTO_NORMAL * 5:
        return True
    return False

def rule_grayhole_timestamp_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de timestampDiff maior do que o esperado,
    sugerindo uma variação anormal nos tempos de chegada dos pacotes.
    """
    TIMESTAMP_DESVIO_NORMAL = baseline.get('timestamp', {}).get('desvio_normal', TIMESTAMP_DESVIO) if baseline else TIMESTAMP_DESVIO
    valor = packet.get('timestampDiff', 0)
    if valor > TIMESTAMP_DESVIO_NORMAL * 4:
        return True
    return False

def rule_grayhole_stnum_crescimento_rapido(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento de StNum mais rápido do que o esperado,
    sugerindo uma possível injeção de tráfego.
    """
    INCREMENTO_ST_NORMAL = baseline.get('StNum', {}).get('incremento_normal', INCREMENTO_ST_NORMAL) if baseline else INCREMENTO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 6:
        return True
    return False

def rule_grayhole_delay_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de delay maior do que o esperado,
    sugerindo uma variação anormal nos tempos de atraso entre os pacotes.
    """
    LIMIAR = baseline.get('delay', {}).get('max_normal', 10) * 2 if baseline else 20
    valor = packet.get('delay', 0)
    if valor > LIMIAR:
        return True
    return False