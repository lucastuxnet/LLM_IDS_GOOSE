def rule_inverse_replay_stnum_desvio_elevado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio padrão de StNum significativamente maior que o esperado, 
    indicando uma possível inversão de sequência.
    """
    media_stnum = baseline.get('StNum', {}).get('media', 0) if baseline else 0
    desvio_stnum = baseline.get('StNum', {}).get('desvio', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('StNum', 0)
    if valor > media_stnum + 3 * desvio_stnum:
        return True
    return False

def rule_inverse_replay_sqnum_desvio_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio padrão de SqNum anormalmente alto, sugerindo uma possível manipulação da sequência.
    """
    media_sqnum = baseline.get('SqNum', {}).get('media', 0) if baseline else 0
    desvio_sqnum = baseline.get('SqNum', {}).get('desvio', INCREMENTO_SQ_NORMAL) if baseline else INCREMENTO_SQ_NORMAL
    valor = packet.get('SqNum', 0)
    if valor > media_sqnum + 3 * desvio_sqnum:
        return True
    return False

def rule_inverse_replay_timestamp_diff_desvio_elevado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio de timestampDiff significativamente maior que o esperado, 
    sugerindo uma possível inversão de replay.
    """
    media_timestamp = baseline.get('timestampDiff', {}).get('media', TIMESTAMP_MEDIA) if baseline else TIMESTAMP_MEDIA
    desvio_timestamp = baseline.get('timestampDiff', {}).get('desvio', TIMESTAMP_DESVIO) if baseline else TIMESTAMP_DESVIO
    valor = packet.get('timestampDiff', 0)
    if valor > media_timestamp + 3 * desvio_timestamp:
        return True
    return False

def rule_inverse_replay_st_diff_desvio_elevado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio de stDiff significativamente maior que o esperado, 
    sugerindo uma possível inversão de sequência.
    """
    media_stdiff = baseline.get('stDiff', {}).get('media', 0) if baseline else 0
    desvio_stdiff = baseline.get('stDiff', {}).get('desvio', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('stDiff', 0)
    if valor > media_stdiff + 3 * desvio_stdiff:
        return True
    return False

def rule_inverse_replay_sq_diff_desvio_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta o desvio de sqDiff anormalmente alto, indicando uma possível manipulação da sequência.
    """
    media_sqdiff = baseline.get('sqDiff', {}).get('media', 0) if baseline else 0
    desvio_sqdiff = baseline.get('sqDiff', {}).get('desvio', INCREMENTO_SQ_NORMAL) if baseline else INCREMENTO_SQ_NORMAL
    valor = packet.get('sqDiff', 0)
    if valor > media_sqdiff + 3 * desvio_sqdiff:
        return True
    return False