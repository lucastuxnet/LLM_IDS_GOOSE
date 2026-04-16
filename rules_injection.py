def rule_injection_sq_num_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do SqNum significativamente maior que o esperado.
    
    A regra é baseada na comparação do desvio padrão do SqNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    LIMIAR = baseline.get('SqNum', {}).get('desvio', 1) * 3 if baseline else 20
    valor = packet.get('SqNum', 0)
    media = baseline.get('SqNum', {}).get('media', 0) if baseline else 0
    desvio = (valor - media) ** 2
    if desvio > LIMIAR ** 2:
        return True
    return False


def rule_injection_st_num_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do StNum significativamente maior que o esperado.
    
    A regra é baseada na comparação do desvio padrão do StNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    LIMIAR = baseline.get('StNum', {}).get('desvio', 1) * 3 if baseline else 20
    valor = packet.get('StNum', 0)
    media = baseline.get('StNum', {}).get('media', 0) if baseline else 0
    desvio = (valor - media) ** 2
    if desvio > LIMIAR ** 2:
        return True
    return False


def rule_injection_cb_status_desvio_padrao(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do cbStatus significativamente maior que o esperado.
    
    A regra é baseada na comparação do desvio padrão do cbStatus com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    LIMIAR = baseline.get('cbStatus', {}).get('desvio', 1) * 3 if baseline else 20
    valor = packet.get('cbStatus', 0)
    media = baseline.get('cbStatus', {}).get('media', 0) if baseline else 0
    desvio = (valor - media) ** 2
    if desvio > LIMIAR ** 2:
        return True
    return False


def rule_injection_sq_num_crescimento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento do SqNum significativamente mais rápido que o esperado.
    
    A regra é baseada na comparação do crescimento do SqNum com o valor esperado.
    Se o crescimento for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    LIMIAR = baseline.get('SqNum', {}).get('incremento', 1) * 3 if baseline else 20
    valor = packet.get('SqNum', 0)
    media = baseline.get('SqNum', {}).get('media', 0) if baseline else 0
    crescimento = valor - media
    if crescimento > LIMIAR:
        return True
    return False


def rule_injection_st_num_crescimento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento do StNum significativamente mais rápido que o esperado.
    
    A regra é baseada na comparação do crescimento do StNum com o valor esperado.
    Se o crescimento for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    LIMIAR = baseline.get('StNum', {}).get('incremento', 1) * 3 if baseline else 20
    valor = packet.get('StNum', 0)
    media = baseline.get('StNum', {}).get('media', 0) if baseline else 0
    crescimento = valor - media
    if crescimento > LIMIAR:
        return True
    return False