def rule_injection_sq_num_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo SqNum significativamente maior que o esperado.
    
    A regra considera um desvio padrão maior que 3 vezes a média como anormal.
    """
    media = baseline.get('SqNum', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('SqNum', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('SqNum', 0)
    if desvio > media * 3:
        return True
    return False

def rule_injection_st_num_crescimento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento anormal do campo StNum em relação à média e desvio.
    
    A regra considera um crescimento maior que 2 vezes a média mais 2 desvios como anormal.
    """
    media = baseline.get('StNum', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('StNum', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('StNum', 0)
    if valor > media + 2 * desvio:
        return True
    return False

def rule_injection_cb_status_mudanca_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta mudanças anormais no campo cbStatus em relação à média e desvio.
    
    A regra considera uma mudança maior que 2 desvios como anormal.
    """
    media = baseline.get('cbStatus', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('cbStatus', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('cbStatus', 0)
    if abs(valor - media) > 2 * desvio:
        return True
    return False

def rule_injection_timestamp_diff_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo timestampDiff significativamente maior que o esperado.
    
    A regra considera um desvio padrão maior que 3 vezes a média como anormal.
    """
    media = baseline.get('timestampDiff', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('timestampDiff', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('timestampDiff', 0)
    if desvio > media * 3:
        return True
    return False

def rule_injection_sq_num_crescimento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento anormal do campo SqNum em relação à média e desvio.
    
    A regra considera um crescimento maior que 2 vezes a média mais 2 desvios como anormal.
    """
    media = baseline.get('SqNum', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('SqNum', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('SqNum', 0)
    if valor > media + 2 * desvio:
        return True
    return False