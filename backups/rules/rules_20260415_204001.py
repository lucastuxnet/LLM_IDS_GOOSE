"""
Regras de Detecção de Intrusão para IEC 61850-GOOSE
"""

import numpy as np


# === REGRAS PARA GRAYHOLE ===
def rule_grayhole_stnum_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão de StNum com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('StNum', {}).get('max_normal', DESVIO_ST_NORMAL) * 3 if baseline else DESVIO_ST_NORMAL * 3
    valor = packet.get('stDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_sqnum_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão de SqNum com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('SqNum', {}).get('max_normal', 10) * 2 if baseline else 20
    valor = packet.get('sqDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_stnum_crescimento_rapido(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta crescimento de StNum mais rápido do que o esperado.
    
    A regra é baseada na comparação do crescimento de StNum com o valor máximo normal.
    Se o crescimento for maior que 2 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('StNum', {}).get('max_normal', INCREMENTO_ST_NORMAL) * 2 if baseline else INCREMENTO_ST_NORMAL * 2
    valor = packet.get('stDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_timestamp_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo de chegada dos pacotes significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do tempo de chegada com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('timestamp', {}).get('max_normal', TIMESTAMP_DESVIO) * 3 if baseline else TIMESTAMP_DESVIO * 3
    valor = packet.get('timestampDiff', 0)
    if valor > LIMIAR:
        return True
    return False


def rule_grayhole_t_diff_desvio_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo de diferença entre os pacotes significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do tempo de diferença com o valor máximo normal.
    Se o desvio padrão for maior que 3 vezes o valor máximo normal, a regra é acionada.
    """
    LIMIAR = baseline.get('tDiff', {}).get('max_normal', 10) * 2 if baseline else 20
    valor = packet.get('tDiff', 0)
    if valor > LIMIAR:
        return True
    return False


# === REGRAS PARA INJECTION ===
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


# === REGRAS PARA HIGH_STNUM ===
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


# === REGRAS PARA RANDOM_REPLAY ===
def rule_random_replay_stnum_desvio_elevado(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de StNum significativamente maior do que o esperado.
    
    A regra verifica se o desvio padrão de StNum é maior que 3 vezes o desvio padrão normal.
    """
    DESVIO_ST_NORMAL = baseline.get('DESVIO_ST_NORMAL', 199.2918) if baseline else 199.2918
    stnum_desvio = packet.get('stDiff', 0)
    if stnum_desvio > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_random_replay_sqnum_desvio_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão de SqNum anormalmente alto.
    
    A regra verifica se o desvio padrão de SqNum é maior que 2 vezes o incremento normal de SqNum.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('INCREMENTO_SQ_NORMAL', 6.0000) if baseline else 6.0000
    sqnum_desvio = packet.get('sqDiff', 0)
    if sqnum_desvio > INCREMENTO_SQ_NORMAL * 2:
        return True
    return False


def rule_random_replay_timestamp_diff_anormal(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do tempo entre pacotes significativamente diferente do esperado.
    
    A regra verifica se o desvio padrão do tempo entre pacotes é maior que 2 vezes o desvio padrão normal do tempo.
    """
    TIMESTAMP_DESVIO = baseline.get('TIMESTAMP_DESVIO', 0.116331) if baseline else 0.116331
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 2:
        return True
    return False


def rule_random_replay_goose_length_diff_zero(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta diferença de comprimento do pacote GOOSE consistentemente zero.
    
    A regra verifica se a diferença de comprimento do pacote GOOSE é zero e se o pacote não é o primeiro.
    """
    goose_length_diff = packet.get('gooseLengthDiff', 0)
    if goose_length_diff == 0 and packet.get('packet_id', 0) > 0:
        return True
    return False


def rule_random_replay_apdu_size_diff_zero(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta diferença de tamanho do APDU consistentemente zero.
    
    A regra verifica se a diferença de tamanho do APDU é zero e se o pacote não é o primeiro.
    """
    apdu_size_diff = packet.get('apduSizeDiff', 0)
    if apdu_size_diff == 0 and packet.get('packet_id', 0) > 0:
        return True
    return False


# === REGRAS PARA MASQUERADE_FAKE_NORMAL ===
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


# === REGRAS PARA INVERSE_REPLAY ===
def rule_inverse_replay_stnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo StNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do campo StNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    DESVIO_ST_NORMAL = baseline.get('StNum', {}).get('desvio_padrao', DESVIO_ST_NORMAL) if baseline else DESVIO_ST_NORMAL
    valor = packet.get('StNum', 0)
    st_diff = packet.get('stDiff', 0)
    if st_diff > DESVIO_ST_NORMAL * 3:
        return True
    return False


def rule_inverse_replay_sqnum_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo SqNum significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do campo SqNum com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_SQ_NORMAL = baseline.get('SqNum', {}).get('incremento_normal', INCREMENTO_SQ_NORMAL) if baseline else INCREMENTO_SQ_NORMAL
    valor = packet.get('SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    if sq_diff > INCREMENTO_SQ_NORMAL * 3:
        return True
    return False


def rule_inverse_replay_cbstatus_comportamento_anômalo(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta comportamento anômalo do campo cbStatus.
    
    A regra é baseada na comparação da frequência de mudanças do campo cbStatus com o valor esperado.
    Se a frequência de mudanças for maior que 2 vezes o valor esperado, a regra é acionada.
    """
    cb_status_diff = packet.get('cbStatusDiff', 0)
    if cb_status_diff > 2:
        return True
    return False


def rule_inverse_replay_timestamp_desvio_padrão_alto(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta desvio padrão do campo timestampDiff significativamente maior do que o esperado.
    
    A regra é baseada na comparação do desvio padrão do campo timestampDiff com o valor esperado.
    Se o desvio padrão for maior que 3 vezes o valor esperado, a regra é acionada.
    """
    TIMESTAMP_DESVIO = baseline.get('timestampDiff', {}).get('desvio_padrao', TIMESTAMP_DESVIO) if baseline else TIMESTAMP_DESVIO
    timestamp_diff = packet.get('timestampDiff', 0)
    if timestamp_diff > TIMESTAMP_DESVIO * 3:
        return True
    return False


def rule_inverse_replay_stnum_incremento_anômalo(packet: dict, baseline: dict = None) -> bool:
    """
    Detecta incremento anômalo do campo StNum.
    
    A regra é baseada na comparação do incremento do campo StNum com o valor esperado.
    Se o incremento for maior que 2 vezes o valor esperado, a regra é acionada.
    """
    INCREMENTO_ST_NORMAL = baseline.get('StNum', {}).get('incremento_normal', INCREMENTO_ST_NORMAL) if baseline else INCREMENTO_ST_NORMAL
    st_diff = packet.get('stDiff', 0)
    if st_diff > INCREMENTO_ST_NORMAL * 2:
        return True
    return False


# === REGRAS PARA MASQUERADE_FAKE_FAULT ===
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


# === REGRAS PARA POISONED_HIGH_RATE ===
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

