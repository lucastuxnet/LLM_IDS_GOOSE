def rule_poisoned_high_rate_alta_taxa_de_stnum(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta taxa de incremento de StNum em relação ao timestampDiff.
    
    A regra considera anômalo se o incremento de StNum for maior que 3 vezes a média.
    """
    LIMIAR = baseline.get('StNum', {}).get('max_normal', INCREMENTO_ST_NORMAL) * 3 if baseline else INCREMENTO_ST_NORMAL * 3
    valor = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > LIMIAR and timestamp_diff > 0:
        return True
    return False

def rule_poisoned_high_rate_alta_taxa_de_sqnum(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta taxa de incremento de SqNum em relação ao timestampDiff.
    
    A regra considera anômalo se o incremento de SqNum for maior que 3 vezes a média.
    """
    LIMIAR = baseline.get('SqNum', {}).get('max_normal', INCREMENTO_SQ_NORMAL) * 3 if baseline else INCREMENTO_SQ_NORMAL * 3
    valor = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > LIMIAR and timestamp_diff > 0:
        return True
    return False

def rule_poisoned_high_rate_alta_variacao_de_stnum(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta variação de StNum em relação à média.
    
    A regra considera anômalo se a variação de StNum for maior que 3 vezes o desvio padrão.
    """
    LIMIAR = baseline.get('StNum', {}).get('max_normal', DESVIO_ST_NORMAL) * 3 if baseline else DESVIO_ST_NORMAL * 3
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > LIMIAR:
        return True
    return False

def rule_poisoned_high_rate_alta_frequencia_de_cbstatus(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta frequência de mudanças no cbStatus em relação ao timestampDiff.
    
    A regra considera anômalo se a frequência de mudanças no cbStatus for maior que 3 vezes a média.
    """
    LIMIAR = baseline.get('cbStatus', {}).get('max_normal', TIMESTAMP_MEDIA) * 3 if baseline else TIMESTAMP_MEDIA * 3
    valor = packet.get('cbStatus', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > LIMIAR and timestamp_diff > 0:
        return True
    return False

def rule_poisoned_high_rate_alta_taxa_de_goose(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta taxa de envio de mensagens GOOSE em relação ao timestampDiff.
    
    A regra considera anômalo se a taxa de envio de mensagens GOOSE for maior que 3 vezes a média.
    """
    LIMIAR = baseline.get('goID', {}).get('max_normal', TIMESTAMP_MEDIA) * 3 if baseline else TIMESTAMP_MEDIA * 3
    valor = packet.get('goID', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > LIMIAR and timestamp_diff > 0:
        return True
    return False