def rule_masquerade_fake_fault_sqnum_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do SqNum significativamente maior do que o esperado.
    
    A regra verifica se o desvio padrão do SqNum é maior que 3 vezes a média.
    """
    media = baseline.get('SqNum', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('SqNum', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('SqNum', 0)
    if desvio > media * 3:
        return True
    return False

def rule_masquerade_fake_fault_cbstatus_inconsistencia(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta inconsistência no cbStatus.
    
    A regra verifica se a diferença no cbStatus é maior que 2 vezes a média.
    """
    media = baseline.get('cbStatus', {}).get('media', 0) if baseline else 0
    valor = packet.get('cbStatusDiff', 0)
    if valor > media * 2:
        return True
    return False

def rule_masquerade_fake_fault_sqnum_stnum_correlacao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta falta de sincronia entre SqNum e StNum.
    
    A regra verifica se a correlação entre SqNum e StNum é menor que 0.5.
    """
    correlacao = baseline.get('SqNum_StNum', {}).get('correlacao', 1) if baseline else 1
    if correlacao < 0.5:
        return True
    return False

def rule_masquerade_fake_fault_sqdiff_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do sqDiff significativamente maior do que o esperado.
    
    A regra verifica se o desvio padrão do sqDiff é maior que 3 vezes a média.
    """
    media = baseline.get('sqDiff', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('sqDiff', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('sqDiff', 0)
    if desvio > media * 3:
        return True
    return False

def rule_masquerade_fake_fault_timestamp_diff_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do timestampDiff significativamente maior do que o esperado.
    
    A regra verifica se o desvio padrão do timestampDiff é maior que 3 vezes a média.
    """
    media = baseline.get('timestampDiff', {}).get('media', 0) if baseline else 0
    desvio = baseline.get('timestampDiff', {}).get('desvio', 0) if baseline else 0
    valor = packet.get('timestampDiff', 0)
    if desvio > media * 3:
        return True
    return False