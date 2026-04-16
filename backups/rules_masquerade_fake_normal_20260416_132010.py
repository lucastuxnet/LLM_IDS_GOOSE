def rule_masquerade_fake_normal_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior do que o esperado.
    
    Comportamento anômalo: O desvio padrão de StNum é maior que 3 vezes o desvio padrão normal.
    """
    DESVIO_ST_NORMAL = baseline.get('stnum', {}).get('desvio_padrao_normal', 199.2918) if baseline else 199.2918
    stnum_desvio_padrao = packet.get('stnum_desvio_padrao', 0)
    if stnum_desvio_padrao > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum significativamente maior do que o esperado.
    
    Comportamento anômalo: O desvio padrão de SqNum é maior que 3 vezes o desvio padrão normal.
    """
    DESVIO_SQ_NORMAL = baseline.get('sqnum', {}).get('desvio_padrao_normal', 10) if baseline else 10
    sqnum_desvio_padrao = packet.get('sqnum_desvio_padrao', 0)
    if sqnum_desvio_padrao > DESVIO_SQ_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento de StNum significativamente diferente do incremento típico.
    
    Comportamento anômalo: O incremento de StNum é maior que 2 vezes o incremento normal.
    """
    INCREMENTO_ST_NORMAL = baseline.get('stnum', {}).get('incremento_normal', 180.0000) if baseline else 180.0000
    stnum_incremento = packet.get('stnum_incremento', 0)
    if stnum_incremento > INCREMENTO_ST_NORMAL * 2:
        return True
    return False


def rule_masquerade_fake_normal_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão dos intervalos de tempo entre os pacotes significativamente maior do que o esperado.
    
    Comportamento anômalo: O desvio padrão dos intervalos de tempo é maior que 3 vezes o desvio padrão normal.
    """
    TIMESTAMP_DESVIO_NORMAL = baseline.get('timestamp', {}).get('desvio_padrao_normal', 0.116331) if baseline else 0.116331
    timestamp_desvio_padrao = packet.get('timestamp_desvio_padrao', 0)
    if timestamp_desvio_padrao > TIMESTAMP_DESVIO_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_goose_length_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tamanho do campo goose significativamente maior do que o esperado.
    
    Comportamento anômalo: O desvio padrão do tamanho do campo goose é maior que 3 vezes o desvio padrão normal.
    """
    GOOSE_LENGTH_DESVIO_NORMAL = baseline.get('goose_length', {}).get('desvio_padrao_normal', 10) if baseline else 10
    goose_length_desvio_padrao = packet.get('goose_length_desvio_padrao', 0)
    if goose_length_desvio_padrao > GOOSE_LENGTH_DESVIO_NORMAL * 3:
        return True
    return False