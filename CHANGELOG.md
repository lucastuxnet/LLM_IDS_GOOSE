# Changelog — SBSEC_2026

All notable changes to this project are documented in this file.  
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v1.1] — 2026-05-13

### Added
- **Seletor interativo de CSV** (portado do SBRC 2026): ao executar a célula de ingestão de dados, o notebook lista automaticamente todos os arquivos `.csv` encontrados no diretório e subdiretórios, exibe tamanho em MB e valida se as colunas obrigatórias (`StNum`, `SqNum`, `class`) estão presentes. O usuário escolhe por número, digita um caminho manual, ou pressiona Enter para o padrão.
- **Filtro FPR com validação cruzada 5-folds** (portado do SBRC 2026): após gerar cada função de regra, o pipeline executa `filter_rules_by_fpr()` sobre o tráfego normal. Funções com `FPR_médio + FPR_desvio > 5%` são automaticamente rejeitadas antes de serem salvas em `rules_raw.py`.
- **Prompt aprimorado com limites normais p5–p95**: a função `make_rules_prompt_from_red_flags()` agora inclui uma tabela de limites `[p5, p95]` por feature calculada sobre o tráfego normal, instruindo o LLM a usar apenas thresholds fora do intervalo normal para reduzir falsos positivos.
- **Pipeline de duas etapas para geração de regras** (espelhando o SBRC 2026):
  - **§8.1** — gera `rules_raw.py` (saída bruta do LLM, preservada para auditoria)
  - **§8.2** — refina `rules_raw.py` → `rules.py` via `clean_rules_file()` (remove markdown, corrige docstrings abertas, valida sintaxe com `ast.parse()`)
- **Backup de `rules_raw.py`**: agora salvo em `backups/rules_raw_<timestamp>.py` junto com `rules.py` e `red_flags.json`.
- **`backup_file()` genérica**: função única que aceita qualquer extensão e qualquer pasta de destino, substituindo as funções de backup fragmentadas anteriores.
- **`normalize_class_column()`**: sanitiza a coluna `class` antes de amostragem (remove `nan`, `None`, strings vazias).
- **`sample_normal_and_attacks()`**: amostragem balanceada com `random_state=42`, compatível com o SBRC 2026.
- **`validate_rules_module()`**: executada automaticamente após §8.2, lista as funções `rule_*` carregadas do `rules.py` gerado.
- **Configuração por classes problemáticas**: suporte a `RULES_PER_CLASS` e `CLASS_SPECIFIC_INSTRUCTIONS` para classes com baixa detecção histórica (`grayhole`, `random_replay`, `masquerade_fake_fault`), aumentando o número de regras geradas e ajustando as instruções do prompt.
- **`baseline_stats.json`**: estatísticas do tráfego normal (mean, std, p5, p95, min, max por feature) agora persistidas em arquivo, com backup automático antes de cada sobrescrita.
- Arquivo `LICENSE` (MIT) adicionado ao repositório.
- Arquivo `CHANGELOG.md` adicionado ao repositório.
- Arquivo `PROMPT.md` atualizado para documentar os três estágios do pipeline: extração de red flags, geração bruta (`rules_raw.py`) e refinamento (`rules.py`).
- `requirements.txt` expandido com `scikit-learn`, `matplotlib`, `seaborn`, `jupyter`, `notebook`, `ipykernel` e `ipywidgets`.

### Changed
- Célula de ingestão de dados (§7) migrada de caminho fixo (`ERENO-2.0-100K.csv`) para seletor interativo com validação e fallback.
- Seções §8.1 e §8.2 renomeadas para espelhar a nomenclatura do SBRC 2026:
  - Antes: §8.1 = extração de red flags, §8.2 = geração de regras (saída única `rules.py`)
  - Agora: §8.1 = extração de red flags + geração de `rules_raw.py`, §8.2 = refinamento `rules_raw.py` → `rules.py`
- Função de backup unificada em `backup_file(filepath, backup_dir_name)` — todas as chamadas de backup (red flags, rules_raw, rules, baseline) passam por esta função.
- `README.md` reescrito com seções de artifact badges, comparação SBRC vs SBSEC, infraestrutura experimental, tempo esperado de execução e tabela completa de outputs gerados.

### Fixed
- Correção de docstrings abertas geradas pelo LLM (`fix_unclosed_docstrings()`) antes de salvar `rules.py`.
- Caracteres Unicode problemáticos (travessões, aspas tipográficas, reticências) substituídos por equivalentes ASCII antes da validação de sintaxe.
- `FPR` calculado corretamente: é uma métrica do tráfego normal, não por classe de ataque — `FP` e `TN` zerados para classes de ataque na matriz de confusão.

---

## [v1.0] — 2026-03-01

### Added
- Notebook inicial `SBSEC_2026_LLM_IDS_GOOSE.ipynb` submetido ao SBSEC 2026.
- Pipeline LLM-driven de quatro estágios: ingestão → extração de red flags → geração de regras → simulação em switch.
- Dataset ERENO–IEC–61850 com 9 classes de ataque (expansão do SBRC 2026 que cobria 5 classes).
- Geração automática de `rules.py` a partir de red flags por LLM (Groq API, modelo `compound`).
- Classificador multi-classe com decisão `BLOCK`/`ALLOW` por pacote.
- Métricas por classe: precision, recall, F1-score, matriz de confusão normalizada.
- Dashboard visual com `matplotlib` e `seaborn`.
- Gerenciador automático e manual de chave API Groq (células §4.2.1 e §4.2.2).
- Sistema de checkpoint (`progresso_regras.json`) com detecção de mudança em `red_flags.json` por hash MD5.
- Sistema de backup em `backups/` para `red_flags.json`, `rules.py` e `baseline_stats.json`.
- Suporte a Google Colab (montagem de Drive) e execução local.
- Arquivo `PROMPT.md` com documentação dos prompts utilizados.
- Arquivo `requirements.txt` com dependências pinadas.
