# Prompt de Geração de Regras — LLM IDS GOOSE (SBSEC 2026)

> **Nota:** Este arquivo documenta os prompts utilizados no pipeline para converter *red flags* em funções Python de detecção.
> A implementação completa está disponível no notebook `SBSEC_2026_LLM_IDS_GOOSE.ipynb`.
>
> Esta versão expande o pipeline do SBRC 2026 para cobrir **9 classes de ataque** e introduz um **segundo estágio de refinamento**:
> o LLM gera primeiro `rules_raw.py` e depois produz a versão limpa `rules.py`.

---

## Estágio 1 — Extração de Red Flags

```
Analyze GOOSE traffic for IEC 61850 substation.

NORMAL (reference means):
{json.dumps(normal_means, indent=2)}

ATTACK class '{attack_class}' means:
{json.dumps(attack_means, indent=2)}

Task: List RED FLAGS (behavioral patterns) that distinguish this attack from normal traffic.

Format each red flag as:

RED FLAG: [name]
FIELDS: [fields]
REASON: [why anomalous per IEC 61850]

Focus on StNum, SqNum, timestampDiff patterns.
```

---

## Estágio 2 — Geração de Regras Brutas (→ `rules_raw.py`)

```
Você é um modelo especializado em detecção de intrusões em tráfego IEC 61850-GOOSE.

=== RED FLAGS IDENTIFICADAS PARA A CLASSE '{attack_class}' ===
{red_flags_text}

Tarefa:
Converta essas red flags em FUNÇÕES DE REGRAS DE DETECÇÃO em Python para identificar
pacotes suspeitos da classe '{attack_class}'.

Regras de saída:
Retorne APENAS código Python válido, sem explicações, comentários extras ou markdown.
Crie de 3 a 5 funções com a forma:

def rule_{attack_class}_<nome_curto>(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    # lógica usando apenas campos presentes em packet
    ...

Use nomes_curto descritivos em snake_case (ex.: jumps_stnum_time_diff, sqnum_reset_pattern).

Restrições:
- NÃO use a coluna/atributo "class"
- Use apenas campos do dataset: 'StNum', 'SqNum', 'timestampDiff', 'cbStatus',
  'stDiff', 'sqDiff', 'gooseLengthDiff', 'cbStatusDiff', 'apduSizeDiff',
  'frameLengthDiff', 'tDiff', 'timeFromLastChange', 'delay', 'goID'
- Cada regra deve combinar DOIS OU MAIS campos
- NÃO use igualdade exata para valores absolutos
- PREFIRA condições relativas: diferenças, comparações (> ou <), padrões de origem/destino
- Capture comportamento semântico do ataque (replay, jumps anômalos, resets, frequência anômala)

Estilo do código:
- Apenas operações básicas (comparações, AND/OR/NOT, soma/subtração)
- Não importe bibliotecas
- Trate campos ausentes com packet.get("campo", valor_padrao)
```

---

## Estágio 3 — Refinamento de Regras (→ `rules.py`)

Este segundo passo envia o conteúdo de `rules_raw.py` de volta ao LLM para limpeza e validação.

```
Você é um especialista em segurança IEC 61850 e desenvolvedor Python sênior.

Abaixo estão funções de detecção geradas automaticamente para o protocolo GOOSE.
Seu trabalho é:
1. Remover funções duplicadas ou semanticamente equivalentes.
2. Corrigir erros de sintaxe Python, se houver.
3. Garantir que NENHUMA função use o campo "class".
4. Garantir que cada função receba apenas `packet: dict` como argumento.
5. Garantir que todas as funções retornem apenas bool (True/False).
6. Manter os nomes originais das funções intactos.
7. Retornar APENAS código Python puro, sem markdown, sem comentários extras fora das docstrings.

=== REGRAS BRUTAS ===
{rules_raw_code}
```

---

## Mensagem de Sistema (System Prompt) — Estágios 2 e 3

```
Você é um especialista em segurança IEC 61850 e desenvolvedor Python.
Dado o contexto e as red flags, você deve retornar SOMENTE código Python válido.
Não inclua explicações, texto em linguagem natural ou markdown. Apenas código Python puro.
```

---

## Parâmetros da LLM

| Parâmetro | Valor |
| --- | --- |
| Modelo | `groq/compound` (GPT-OSS 120B / Llama 4 Scout) |
| Temperature | 0 |
| Max tokens | 2048 |
| Top_p | 1 |
| Retries (rate-limit) | 5 (exponential backoff) |

---

## Fluxo de Arquivos

```
Red Flags (LLM, estágio 1)
        │
        ▼
  rules_raw.py     ← saída bruta do LLM (estágio 2), preservada para auditoria
        │
        ▼
    rules.py        ← versão refinada (estágio 3), usada na avaliação
        │
        ▼
  Simulação + Avaliação
```

---

## Exemplo de Saída Esperada

Para a classe `masquerade_fake_fault`:

```python
def rule_masquerade_fake_fault_stnum_cbstatus_jump(packet: dict) -> bool:
    """Detecta salto anômalo em StNum combinado com cbStatus inesperado."""
    st_diff = packet.get("stDiff", 0)
    cb_status = packet.get("cbStatus", 0)
    ts_diff = packet.get("timestampDiff", 1)
    return st_diff > 10 and cb_status == 1 and ts_diff < 0.005

def rule_masquerade_fake_fault_sqnum_reset_with_stnum(packet: dict) -> bool:
    """Detecta reset de SqNum enquanto StNum avança."""
    sq_diff = packet.get("sqDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return sq_diff < 0 and st_diff > 0

def rule_masquerade_fake_fault_high_rate_cbstatus(packet: dict) -> bool:
    """Detecta mudanças de cbStatus em alta frequência temporal."""
    cb_diff = packet.get("cbStatusDiff", 0)
    t_diff = packet.get("tDiff", 1)
    return abs(cb_diff) > 0 and t_diff < 0.002
```

---

## Classes de Ataque Cobertas

| Classe | Padrão Principal |
| --- | --- |
| `grayhole` | Dropping seletivo + gaps de SqNum |
| `high_StNum` | Saltos extremos de StNum |
| `injection` | Frames forjados com timestamps anômalos |
| `inverse_replay` | Timestamps decrescentes + StNum retroativo |
| `masquerade_fake_fault` | cbStatus=1 forçado + StNum jump |
| `masquerade_fake_normal` | cbStatus=0 forçado + SqNum reset |
| `poisoned_high_rate` | tDiff muito baixo (flooding) |
| `random_replay` | SqNum desordenado + stDiff inconsistente |

---

## Referência no Código Fonte

| Função | Localização no Notebook |
| --- | --- |
| `make_red_flags_prompt()` | §4 — Red Flag Extraction |
| `make_rules_prompt_from_red_flags()` | §5 — Raw Rule Generation |
| `make_refinement_prompt()` | §6 — Rule Refinement |
| `save_rules_raw()` | §5 — salva `rules_raw.py` |
| `save_rules_refined()` | §6 — salva `rules.py` |
