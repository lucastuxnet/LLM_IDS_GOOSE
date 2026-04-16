def rule_masquerade_fake_fault_stnum_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio padrão de StNum significativamente maior que o esperado,
    indicando uma possível tentativa de mascarar o comportamento.
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', 199.2918) if baseline else 199.2918
    stnum = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 2:
        return True
    return False

def rule_masquerade_fake_fault_sqnum_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio padrão de SqNum significativamente maior que o esperado,
    indicando uma possível tentativa de mascarar o comportamento.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000) if baseline else 6.0000
    sqnum = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > INCREMENTO_SQ_NORMAL * 3:
        return True
    return False

def rule_masquerade_fake_fault_stnum_incrimento_anômalo(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o incremento de StNum significativamente maior ou menor que o esperado,
    indicando uma possível tentativa de mascarar o comportamento.
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', 180.0000) if baseline else 180.0000
    stnum = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 2 or st_diff < -INCREMENTO_ST_NORMAL * 2:
        return True
    return False

def rule_masquerade_fake_fault_timestamp_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio padrão do tempo de chegada dos pacotes significativamente maior que o esperado,
    indicando uma possível tentativa de mascarar o comportamento.
    """
    TIMESTAMP_DESVIO = baseline.get('TIMESTAMP_DESVIO', 0.116331) if baseline else 0.116331
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 3:
        return True
    return False

def rule_masquerade_fake_fault_stnum_cbstatus_correlação(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta a correlação entre StNum e cbStatus significativamente diferente da esperada,
    indicando uma possível tentativa de mascarar o comportamento.
    """
    # Essa regra é mais complexa e pode exigir uma abordagem mais sofisticada
    # para calcular a correlação entre StNum e cbStatus.
    # Para simplificar, vamos considerar que a correlação é anormal se o valor
    # de StNum for significativamente maior ou menor que o valor de cbStatus.
    stnum = packet.get('StNum', 0)
    cbstatus = packet.get('cbStatus', 0)
    if stnum > cbstatus * 2 or stnum < cbstatus / 2:
        return True
    return False