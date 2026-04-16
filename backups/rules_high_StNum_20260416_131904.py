def rule_high_StNum_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior que o desvio padrão médio.
    
    A regra é baseada na comparação do desvio padrão do StNum com o desvio padrão médio.
    Se o desvio padrão do StNum for maior que 3 vezes o desvio padrão médio, a regra é acionada.
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', 199.2918) if baseline else 199.2918
    stnum_desvio = packet.get('stDiff', 0)
    if stnum_desvio > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_high_StNum_sqnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento de SqNum anormalmente alto em relação ao incremento médio.
    
    A regra é baseada na comparação do incremento do SqNum com o incremento médio.
    Se o incremento do SqNum for maior que 5 vezes o incremento médio, a regra é acionada.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000) if baseline else 6.0000
    sqnum_incremento = packet.get('sqDiff', 0)
    if sqnum_incremento > INCREMENTO_SQ_NORMAL * 5:
        return True
    return False


def rule_high_StNum_timestamp_diff_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta tempo de diferença entre os timestamps anormalmente alto em relação ao tempo médio de mudança.
    
    A regra é baseada na comparação do tempo de diferença entre os timestamps com o tempo médio de mudança.
    Se o tempo de diferença for maior que 10 vezes o tempo médio de mudança, a regra é acionada.
    """
    TIMESTAMP_MEDIA = baseline.get('TIMESTAMP_MEDIA', 0.100067) if baseline else 0.100067
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_MEDIA * 10:
        return True
    return False


def rule_high_StNum_stnum_crescimento_exponencial(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento de StNum exponencial em relação ao crescimento médio.
    
    A regra é baseada na comparação do crescimento do StNum com o crescimento médio.
    Se o crescimento do StNum for maior que 5 vezes o crescimento médio, a regra é acionada.
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', 180.0000) if baseline else 180.0000
    stnum_crescimento = packet.get('stDiff', 0)
    if stnum_crescimento > INCREMENTO_ST_NORMAL * 5:
        return True
    return False


def rule_high_StNum_cbstatus_mudança_frequente(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta mudança no valor de cbStatus mais frequente do que o esperado.
    
    A regra é baseada na comparação da frequência de mudança do cbStatus com a frequência média de mudança.
    Se a frequência de mudança for maior que 5 vezes a frequência média de mudança, a regra é acionada.
    """
    cbstatus_mudança = packet.get('cbStatusDiff', 0)
    if cbstatus_mudança > 5:
        return True
    return False