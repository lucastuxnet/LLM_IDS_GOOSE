"""
Regras de Detecção de Intrusão para IEC 61850-GOOSE
"""

import numpy as np


# === REGRAS PARA GRAYHOLE ===
def rule_grayhole_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo StNum, indicando variação anormal no número de sequência.
    
    A regra é baseada na comparação do desvio padrão do campo StNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    DESVIO_ST_NORMAL = baseline.get('StNum', {}).get('desvio_padrao', DESVIO_ST_NORMAL)
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False

def rule_grayhole_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo SqNum, indicando variação anormal no número de sequência.
    
    A regra é baseada na comparação do desvio padrão do campo SqNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('SqNum', {}).get('incremento_normal', INCREMENTO_SQ_NORMAL)
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > INCREMENTO_SQ_NORMAL * 3:
        return True
    return False

def rule_grayhole_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo timestampDiff, indicando variação anormal no tempo de chegada dos pacotes.
    
    A regra é baseada na comparação do desvio padrão do campo timestampDiff com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    TIMESTAMP_DESVIO = baseline.get('timestampDiff', {}).get('desvio_padrao', TIMESTAMP_DESVIO)
    valor = packet.get('timestampDiff', 0)
    if valor > TIMESTAMP_DESVIO * 3:
        return True
    return False

def rule_grayhole_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento anormal no campo StNum, indicando anormalidade no número de sequência.
    
    A regra é baseada na comparação do incremento do campo StNum com o valor esperado.
    Se o incremento for maior ou menor que 3 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_ST_NORMAL = baseline.get('StNum', {}).get('incremento_normal', INCREMENTO_ST_NORMAL)
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 3 or st_diff < INCREMENTO_ST_NORMAL / 3:
        return True
    return False

def rule_grayhole_cbstatus_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto no campo cbStatus, indicando variação anormal no status do controle de bloqueio.
    
    A regra é baseada na comparação do desvio padrão do campo cbStatus com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    valor = packet.get('cbStatus', 0)
    cb_status_diff = packet.get('cbStatusDiff', 0)
    if cb_status_diff > 3:
        return True
    return False


# === REGRAS PARA INJECTION ===
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


# === REGRAS PARA HIGH_STNUM ===
def rule_high_StNum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior que o desvio padrão médio.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o desvio padrão for anormal, False caso contrário
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', DESVIO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_high_StNum_crescimento_exponencial(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento exponencial de StNum em relação ao crescimento médio.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o crescimento for exponencial, False caso contrário
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', INCREMENTO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 5:
        return True
    return False


def rule_high_StNum_crescimento_acelerado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento acelerado de StNum em relação ao crescimento médio.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o crescimento for acelerado, False caso contrário
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', INCREMENTO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 4:
        return True
    return False


def rule_high_StNum_desvio_medio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio médio de StNum significativamente maior que o desvio médio esperado.
    
    :param packet: Dicionário contendo os dados do pacote
    :param baseline: Dicionário contendo os valores de baseline (opcional)
    :return: True se o desvio médio for anormal, False caso contrário
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', DESVIO_ST_NORMAL)
    st_num = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 2.5:
        return True
    return False


# === REGRAS PARA RANDOM_REPLAY ===
def rule_random_replay_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto nos valores de StNum, indicando uma variação anormal.
    
    A regra é baseada na comparação do desvio padrão dos valores de StNum com o dobro do desvio padrão normal.
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', 199.2918) if baseline else 199.2918
    LIMIAR = DESVIO_ST_NORMAL * 2
    stnum_desvio_padrão = packet.get('stDiff', 0)
    if stnum_desvio_padrão > LIMIAR:
        return True
    return False


def rule_random_replay_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto nos valores de SqNum, indicando uma variação anormal.
    
    A regra é baseada na comparação do desvio padrão dos valores de SqNum com o dobro do desvio padrão normal.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000) if baseline else 6.0000
    LIMIAR = INCREMENTO_SQ_NORMAL * 3
    sqnum_desvio_padrão = packet.get('sqDiff', 0)
    if sqnum_desvio_padrão > LIMIAR:
        return True
    return False


def rule_random_replay_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão alto nos intervalos de tempo, indicando uma variação anormal.
    
    A regra é baseada na comparação do desvio padrão dos intervalos de tempo com o triplo do desvio padrão normal.
    """
    TIMESTAMP_DESVIO = baseline.get('TIMESTAMP_DESVIO', 0.116331) if baseline else 0.116331
    LIMIAR = TIMESTAMP_DESVIO * 3
    timestamp_desvio_padrão = packet.get('timestampDiff', 0)
    if timestamp_desvio_padrão > LIMIAR:
        return True
    return False


def rule_random_replay_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento anormal nos valores de StNum, indicando uma variação anormal.
    
    A regra é baseada na comparação do incremento dos valores de StNum com o triplo do incremento normal.
    """
    INCREMENTO_ST_NORMAL = baseline.get('INCREMENTO_ST_NORMAL', 180.0000) if baseline else 180.0000
    LIMIAR = INCREMENTO_ST_NORMAL * 3
    stnum_incremento = packet.get('stDiff', 0)
    if stnum_incremento > LIMIAR or stnum_incremento < -LIMIAR:
        return True
    return False


def rule_random_replay_cbstatus_inconsistente(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta inconsistência nos valores de cbStatus, indicando uma possível manipulação dos dados.
    
    A regra é baseada na comparação do valor de cbStatus com o valor esperado.
    """
    cbstatus_esperado = baseline.get('cbStatus', 0) if baseline else 0
    cbstatus_atual = packet.get('cbStatus', 0)
    if cbstatus_atual != cbstatus_esperado:
        return True
    return False


# === REGRAS PARA MASQUERADE_FAKE_NORMAL ===
def rule_masquerade_fake_normal_stnum_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão de StNum for anormal, False caso contrário.
    """
    DESVIO_ST_NORMAL = baseline.get('stnum', {}).get('desvio_padrao', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_sqnum_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão de SqNum for anormal, False caso contrário.
    """
    DESVIO_SQ_NORMAL = baseline.get('sqnum', {}).get('desvio_padrao', 10) if baseline else 10
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > DESVIO_SQ_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_stnum_incremento_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento de StNum significativamente maior ou menor que o incremento típico.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o incremento de StNum for anormal, False caso contrário.
    """
    INCREMENTO_ST_NORMAL = baseline.get('stnum', {}).get('incremento', INCREMENTO_ST_NORMAL) if baseline else INCREMENTO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 3 or st_diff < -INCREMENTO_ST_NORMAL * 3:
        return True
    return False


def rule_masquerade_fake_normal_timestamp_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo de chegada dos pacotes significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão do tempo de chegada for anormal, False caso contrário.
    """
    TIMESTAMP_DESVIO = baseline.get('timestamp', {}).get('desvio_padrao', TIMESTAMP_DESVIO) if baseline else TIMESTAMP_DESVIO
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 3:
        return True
    return False


def rule_masquerade_fake_normal_goose_length_desvio_padrão(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tamanho do pacote GOOSE significativamente maior que o desvio padrão médio.
    
    Parâmetros:
    packet (dict): Dicionário contendo os dados do pacote.
    baseline (dict): Dicionário contendo os valores de baseline (opcional).
    
    Retorno:
    bool: True se o desvio padrão do tamanho do pacote GOOSE for anormal, False caso contrário.
    """
    GOOSE_LENGTH_DESVIO = baseline.get('goose', {}).get('desvio_padrao', 10) if baseline else 10
    goose_length_diff = packet.get('gooseLengthDiff', 0)
    if goose_length_diff > GOOSE_LENGTH_DESVIO * 3:
        return True
    return False


# === REGRAS PARA INVERSE_REPLAY ===
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


# === REGRAS PARA MASQUERADE_FAKE_FAULT ===
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


# === REGRAS PARA POISONED_HIGH_RATE ===
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

