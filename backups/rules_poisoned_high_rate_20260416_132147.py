def rule_poisoned_high_rate_alta_taxa_de_stnum(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta taxa de incremento de StNum em relação ao timestampDiff.
    
    A regra considera anômalo se o incremento de StNum for maior que 3 vezes a média normal.
    """
    media_stnum = baseline.get('INCREMENTO_ST_NORMAL', 180.0000)
    valor = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > media_stnum * 3 and timestamp_diff < 1:
        return True
    return False

def rule_poisoned_high_rate_alta_taxa_de_sqnum(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta taxa de incremento de SqNum em relação ao timestampDiff.
    
    A regra considera anômalo se o incremento de SqNum for maior que 3 vezes a média normal.
    """
    media_sqnum = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000)
    valor = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > media_sqnum * 3 and timestamp_diff < 1:
        return True
    return False

def rule_poisoned_high_rate_alta_variacao_de_stnum(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta variação de StNum em relação à média.
    
    A regra considera anômalo se a variação de StNum for maior que 2 vezes o desvio padrão normal.
    """
    desvio_stnum = baseline.get('DESVIO_ST_NORMAL', 199.2918)
    valor = packet.get('stDiff', 0)
    if valor > desvio_stnum * 2:
        return True
    return False

def rule_poisoned_high_rate_alta_taxa_de_goose(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta taxa de incremento de gooseLengthDiff em relação ao timestampDiff.
    
    A regra considera anômalo se o incremento de gooseLengthDiff for maior que 3 vezes a média normal.
    """
    media_timestamp = baseline.get('TIMESTAMP_MEDIA', 0.100067)
    valor = packet.get('gooseLengthDiff', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > media_timestamp * 3 and timestamp_diff < 1:
        return True
    return False

def rule_poisoned_high_rate_alta_frequencia_de_cbstatus(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta alta frequência de mudanças no cbStatus em relação ao timestampDiff.
    
    A regra considera anômalo se a frequência de mudanças no cbStatus for maior que 2 vezes a média normal.
    """
    media_timestamp = baseline.get('TIMESTAMP_MEDIA', 0.100067)
    valor = packet.get('cbStatus', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if valor > media_timestamp * 2 and timestamp_diff < 1:
        return True
    return False