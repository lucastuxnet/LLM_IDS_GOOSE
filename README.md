# From Red Flags to Detection Rules

## An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection — Extended Evaluation for SBSEC 2026

> **Authors:** Lucas A. Martins¹, Camilla B. Quincozes¹², Silvio E. Quincozes¹², Giovanni Siervo¹, Marcelo Caggiani Luizelli²  
> ¹ Universidade Federal de Uberlândia (UFU) – Uberlândia, Brazil  
> ² Universidade Federal do Pampa (UNIPAMPA) – Alegrete, Brazil  
> `{lucas.martins, camillaquincozes, sequincozes}@ufu.br`
> `{marceloluizelli}@unipampa.edu.br

---

## Artifact Badges

This repository complies with the following artifact evaluation badges:

| Badge | Status | Description |
| --- | --- | --- |
| **Available (D)** | Source code, notebook, and sample data are publicly available in this repository. |
| **Functional (F)** | The notebook can be executed from start to finish (requires Groq API key). |
| **Sustainable (S)** | Modular structure, fixed dependencies in `requirements.txt`, clear documentation. |
| **Reproducible (R)** | Fixed random seeds (`random_state=42`) and step-by-step documentation for experiment reproduction. |

---

## Overview

This repository accompanies the proof-of-concept notebook submitted to **SBSEC 2026**. It extends the original pipeline presented at SBRC 2026 with a broader evaluation: the dataset now covers **9 attack classes** (up from 5), the generated rule set is larger and more granular, and the evaluation pipeline includes multi-class confusion matrices, per-class metrics, rule-level latency analysis, and extended statistical baselines.

The approach removes the need for domain experts to write rules by hand: given labeled samples from the ERENO dataset, an LLM identifies behavioral *red flags* and translates them into executable Python rules. Those rules are then evaluated inside a programmable switch simulator for real-time detection.

The key evolution from SBRC 2026 to SBSEC 2026 is:

- **Larger dataset:** full ERENO 2.0 with 9 attack classes (vs. 5 in SBRC)
- **Two-stage rule generation:** raw LLM output saved as `rules_raw.py`, then refined into `rules.py`
- **Richer evaluation:** per-class precision/recall/F1, normalized confusion matrices, latency distribution per rule
- **Baseline statistics:** `baseline_stats.json` captures normal-traffic statistics used as reference in prompts

---

## Problem Statement

Specification-based Intrusion Detection Systems (IDS) are widely adopted in IEC 61850 substations due to their **low computational overhead** and **interpretability**. However, they rely on rules written manually by domain experts — a costly, hard-to-scale, and poorly adaptable process.

The GOOSE protocol, in particular, was not designed with robust native security mechanisms, making it vulnerable to:

- **Denial-of-Service (DoS)** / *poisoned_high_rate*
- **Message Injection** (*masquerade_fake_fault*, *masquerade_fake_normal*)
- **Replay attacks** (*inverse_replay*, *random_replay*)
- **Grayhole**
- **High StNum** (*high_StNum*)
- **Injection** (*injection*)

---

## Pipeline

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Labeled GOOSE  │───▶│ Red Flag Extract.│───▶│  Rule Generation  │───▶│  Rule Refinement │───▶│ Switch Simulation│
│  Dataset        │     │  (LLM-based)     │     │  (rules_raw.py)   │     │  (rules.py)      │     │  (Real-time)     │
│  (ERENO 2.0)    │     │                  │     │                   │     │                  │     │                  │
└─────────────────┘     └──────────────────┘     └───────────────────┘     └──────────────────┘     └──────────────────┘
```

| Stage | Responsibility |
| --- | --- |
| **1. Source Ingestion** | Loads the ERENO dataset, selects relevant features, and prepares structured prompts |
| **2. Red Flag Extraction** | LLM inspects normal and attack samples to identify suspicious patterns per class |
| **3. Raw Rule Generation** | Translates red flags into Python functions and saves as `rules_raw.py` |
| **4. Rule Refinement** | A second LLM pass cleans, deduplicates, and validates the raw rules into `rules.py` |
| **5. Simulated Deployment** | Applies the rules over GOOSE traffic in a programmable switch simulator |

> **Note on two-stage rule generation:** The notebook first saves the raw LLM output to `rules_raw.py` (preserving the original generation for auditability), then performs a refinement pass that produces the clean `rules.py` used in evaluation. This mirrors the workflow of the companion SBRC 2026 repository and ensures traceability of each rule back to its source red flags.

---

## Dataset

The pipeline uses the **ERENO–IEC–61850 2.0** dataset, a public collection of labeled GOOSE traffic samples under normal conditions and various attack scenarios.

### Training Dataset (`small_dataset/train.csv`)

Used by the LLM to identify red flags and generate detection rules:

- **Samples:** ~207
- **Original features:** 52 columns (15 selected for LLM prompts)
- **Classes:** up to 9 types (1 normal + 8 attacks)

### Test Dataset (`small_dataset/test.csv`)

Used for rule execution and validation:

- **Samples:** varies per run
- **Classes:** same 9 distinct types as training

### Full Class Distribution

| Class | Type | Notes |
| --- | --- | --- |
| `normal` | Legitimate traffic | Reference for red-flag extraction |
| `grayhole` | Attack | Selective packet dropping |
| `high_StNum` | Attack | Anomalous state-number jumps |
| `injection` | Attack | Forged GOOSE frames |
| `inverse_replay` | Attack | Chronologically reversed replay |
| `masquerade_fake_fault` | Attack | Fake fault injection |
| `masquerade_fake_normal` | Attack | Fake normal-state masquerade |
| `poisoned_high_rate` | Attack | High-rate flooding / DoS |
| `random_replay` | Attack | Random-order replay |

### Features Used in the Prompt

The LLM generates rules based on the following 15 features:

| Category | Features |
| --- | --- |
| Protocol-level | `SqNum`, `StNum`, `cbStatus`, `goID` |
| Temporal | `timestampDiff`, `tDiff`, `timeFromLastChange`, `delay` |
| Derived (differences) | `stDiff`, `sqDiff`, `gooseLengthDiff`, `cbStatusDiff`, `apduSizeDiff`, `frameLengthDiff` |
| Label (reference only) | `class` — not used inside rules, only to separate normal from attack samples |

> **Note:** The `class` column is used exclusively for the LLM to differentiate normal from attack samples. It is **not** used inside the generated detection functions.

---

## Repository Structure

```
.
├── SBSEC_2026_LLM_IDS_GOOSE.ipynb      # Main notebook (proof of concept)
├── rules_raw.py                          # Raw LLM-generated rules (before refinement)
├── rules.py                              # Clean & refined detection rules (latest version)
├── requirements.txt                      # Python dependencies (pinned versions)
├── .env                                  # API key file (not versioned — add to .gitignore)
├── LICENSE                               # MIT License
├── PROMPT.md                             # Prompts used in the pipeline (documented)
│
├── small_dataset/                        # Dataset files
│   ├── train.csv                         # Training dataset – ~207 samples, 52 features
│   └── test.csv                          # Test dataset – same feature set
│
├── backups/                              # Backup of previous rule versions
│   ├── rules_<timestamp>.py             # Older version of refined rules
│   ├── rules_raw_<timestamp>.py         # Older version of raw LLM rules
│   └── ...                              # Additional timestamped backups
│
├── old_rules/                            # Legacy rule files (pre-pipeline versions)
├── old_dashboard/                        # Backup of previous dashboard outputs
├── old_matriz/                           # Backup of previous matrix outputs
├── old_statistic/                        # Backup of previous statistics outputs
│
├── baseline_stats.json                   # Normal-traffic baseline statistics for prompts
├── red_flags.json                        # Red flags extracted per attack class
├── red_flags_corrigido.json              # Corrected/validated red flags
├── progresso_regras.json                 # Rule generation progress checkpoint
├── relatorio_completo.json               # Full evaluation report (JSON)
│
├── matriz_regras_ataques.csv             # Rule × attack class trigger-count matrix
├── matriz_regras_ataques_plot.png        # Stacked horizontal bar chart of the matrix
├── deteccoes_por_amostra.csv             # Per-sample detection flags
├── deteccoes_agregado_classes.csv        # Total detections per attack class
├── latencia_regras.csv                   # Per-rule execution latency (µs)
│
├── confianca_por_classe.csv              # Confidence scores per class
├── resultados_classificacao.csv          # BLOCK/ALLOW decisions for each sample
├── metricas_classificacao.txt            # Human-readable classification metrics
├── metricas_por_classe.csv              # Precision, recall, F1 per class
├── metricas_multiclasse.csv             # Multi-class aggregate metrics
│
├── matriz_confusao.csv                   # Binary confusion matrix
├── matriz_confusao_completa.csv          # Full multi-class confusion matrix
├── matriz_confusao_multiclasse.csv       # Multi-class counts
├── matriz_confusao_normalizada.csv       # Row-normalized confusion matrix
├── matriz_confusao_percentual.csv        # Percentual confusion matrix
│
├── dashboard_deteccao.png                # Detection overview dashboard
├── dashboard_metricas_deteccao.png       # Metrics dashboard
├── dashboard_completo_deteccao.png       # Full combined dashboard
├── distribuicao_amostras.png             # Class distribution chart
├── grafico_acertos_erros.png             # Hits vs. misses chart
├── grafico_metricas_por_classe.png       # Per-class metrics chart
├── matriz_confusao.png                   # Confusion matrix heatmap
├── matriz_confusao_dual.png              # Side-by-side normalized/absolute matrices
├── matriz_confusao_multiclasse_plot.png  # Multi-class confusion heatmap
└── matriz_confusao_multiclasse_plot_percent.png  # Percentual multi-class heatmap
```

---

## Experimental Infrastructure

The experiments described in the paper were conducted on the following setup:

| Component | Specification |
| --- | --- |
| **Operating System** | Ubuntu 24.04 LTS (64-bit) |
| **CPU** | Intel® Core™ i7 (details in paper) |
| **RAM** | 16 GB+ DDR4/DDR5 |
| **Python** | 3.12+ (CPython) |
| **GPU** | Not required — all inference is performed via Groq Cloud API |
| **LLM Model** | `groq/compound` (accessed via Groq API key) |

> **Note:** The pipeline uses cloud-based LLM inference. No local GPU is needed. A stable internet connection is required to call the Groq API.

---

## Requirements

- Python 3.12+
- A [Groq](https://console.groq.com) account and API key (with access to the `compound` model)
- Jupyter Notebook or JupyterLab (to run the `.ipynb` file)

### Main dependencies

```
numpy==2.3.3
pandas==2.3.3
groq==1.1.2
python-dotenv==1.0.0
httpx==0.28.1
pydantic>=1.9.0
jupyter>=1.0.0
notebook>=7.0.0
matplotlib>=3.8.0
seaborn>=0.13.0
scikit-learn>=1.4.0
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/lucastuxnet/SBSEC_2026.git
cd SBSEC_2026

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file at the project root with your Groq API key:

```
GROQ_API_KEY=gsk_...
```

> **Warning:** never commit the `.env` file. Add it to `.gitignore`.

---

## Usage Instructions

### Step-by-Step Commands

Follow these commands in order to reproduce the full experiment:

```bash
# 1. Clone the repository
git clone https://github.com/lucastuxnet/SBSEC_2026.git
cd SBSEC_2026

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
cp .env.example .env
# Edit .env and insert your Groq API key: GROQ_API_KEY=gsk_...

# 5. Launch the notebook
jupyter notebook SBSEC_2026_LLM_IDS_GOOSE.ipynb
```

### Minimal Test

To verify that the environment is correctly configured, run:

```bash
python -c "import pandas, groq, matplotlib, seaborn, sklearn; print('Dependencies OK')"
```

---

## Running the Notebook

Open the notebook in Jupyter or VSCode and run the cells in order:

```bash
jupyter notebook SBSEC_2026_LLM_IDS_GOOSE.ipynb
```

| Section | What it does |
| --- | --- |
| **§1 – Setup** | Installs dependencies, imports libraries, and configures Groq client |
| **§2 – Data Ingestion** | Loads the ERENO dataset, selects relevant features, displays class distribution |
| **§3 – Baseline Statistics** | Computes normal-traffic statistics and saves to `baseline_stats.json` |
| **§4 – Red Flag Extraction** | Sends samples to the LLM; extracts suspicious behavioral patterns per attack class |
| **§5 – Raw Rule Generation** | Translates red flags into Python detection functions; saves as `rules_raw.py` |
| **§6 – Rule Refinement** | Second LLM pass cleans and validates raw rules; saves refined version as `rules.py` |
| **§7 – Switch Simulation** | Applies the rules in simulated real-time (BLOCK / ALLOW) over test traffic |
| **§8 – Detection Evaluation** | Computes per-class precision, recall, F1, and multi-class confusion matrices |
| **§9 – Latency Evaluation** | Measures per-rule execution overhead for real-time viability |
| **§10 – Dashboard** | Generates combined visual dashboards of detection metrics and confusion matrices |

> **Two-stage rule generation (§5 → §6):** The notebook always saves the raw LLM output first (`rules_raw.py`), then performs a refinement pass that produces the clean `rules.py`. This ensures the original generation is preserved for auditability and comparison.

---

### Expected Execution Time & Resources

| Stage | Approximate Time | Notes |
| --- | --- | --- |
| **Setup + Data Loading (§1–§2)** | < 5 seconds | Imports and CSV loading |
| **Baseline Statistics (§3)** | < 3 seconds | Pandas groupby on training data |
| **Red Flag Extraction (§4)** | 2–5 minutes | 9 attack classes × API calls (rate-limit aware) |
| **Raw Rule Generation (§5)** | 3–8 minutes | May trigger exponential-backoff retries |
| **Rule Refinement (§6)** | 1–3 minutes | One LLM pass per class to clean raw output |
| **Rule Execution + Matrices (§7–§8)** | 10–60 seconds | Rules applied to all test samples |
| **Latency + Dashboard (§9–§10)** | < 5 seconds | Timing measurements and plot rendering |
| **Total (typical)** | **7–20 minutes** | Varies with Groq API availability |

### Resource Usage

| Metric | Peak Value |
| --- | --- |
| **Memory (RAM)** | ~1.5 GB |
| **Disk (outputs)** | ~100 MB for all generated CSVs, JSONs and plots |
| **Network** | ~100 KB per LLM API call (prompt + response) |
| **GPU** | Not used |

> **If rate-limited by Groq**, the notebook uses exponential backoff and will retry automatically up to 5 times per call.

---

## Generated Outputs & Artifacts

After running the complete notebook, the following files will be created in the project root:

| File | Description | Format |
| --- | --- | --- |
| `baseline_stats.json` | Normal-traffic statistics used as LLM reference | JSON |
| `red_flags.json` | Red flags identified by the LLM for each attack class | JSON |
| `rules_raw.py` | Raw LLM-generated rules (before refinement) | Python |
| `rules.py` | Clean, refined detection rules (used in evaluation) | Python |
| `matriz_regras_ataques.csv` | Trigger-count matrix: rules × attack classes | CSV |
| `matriz_regras_ataques_plot.png` | Stacked horizontal bar chart of the matrix | PNG |
| `deteccoes_por_amostra.csv` | Per-sample detection flags | CSV |
| `deteccoes_agregado_classes.csv` | Total detections per attack class | CSV |
| `latencia_regras.csv` | Per-rule execution latency (mean, std, min, max, P99 in µs) | CSV |
| `resultados_classificacao.csv` | BLOCK/ALLOW decisions for each sample | CSV |
| `metricas_por_classe.csv` | Precision, recall, F1-score per attack class | CSV |
| `metricas_multiclasse.csv` | Multi-class aggregate metrics | CSV |
| `metricas_classificacao.txt` | Human-readable classification report | TXT |
| `confianca_por_classe.csv` | Rule confidence scores per class | CSV |
| `matriz_confusao.csv` | Binary confusion matrix | CSV |
| `matriz_confusao_completa.csv` | Full multi-class confusion matrix | CSV |
| `matriz_confusao_normalizada.csv` | Row-normalized confusion matrix | CSV |
| `matriz_confusao_percentual.csv` | Percentual confusion matrix | CSV |
| `dashboard_completo_deteccao.png` | Full combined detection dashboard | PNG |
| `grafico_metricas_por_classe.png` | Per-class metrics bar chart | PNG |
| `matriz_confusao_multiclasse_plot.png` | Multi-class confusion heatmap | PNG |
| `matriz_confusao_multiclasse_plot_percent.png` | Percentual multi-class heatmap | PNG |

---

## Comparison with SBRC 2026

This repository extends the companion work at [SBRC_2026](https://github.com/lucastuxnet/SBRC_2026). Key differences:

| Aspect | SBRC 2026 | SBSEC 2026 |
| --- | --- | --- |
| **Attack classes** | 5 | 9 |
| **Dataset size** | ~207 train + 200 K test | small_dataset (train + test) |
| **Rule generation** | Single pass → `rules.py` | Two passes: `rules_raw.py` → `rules.py` |
| **Evaluation depth** | Precision/recall/F1 | Full multi-class matrices + dashboards |
| **Latency reporting** | Per-rule (mean) | Per-rule (mean, std, min, max, P99) |
| **Baseline statistics** | Inline in prompts | Persisted to `baseline_stats.json` |

---

## Expected Results

- Automatically generated Python rules detect anomalous behavior across all ERENO attack classes
- Low per-packet operational overhead, suitable for real-time substation environments
- Reproducible pipeline: every run starts from the labeled dataset and ends with auditable rules
- Two-stage rule generation preserves traceability from raw LLM output to refined detection functions

---

## Conclusions and Future Work

This work demonstrates that LLMs can replace the manual rule-writing step in specification-based IDS, reducing reliance on domain experts and improving adaptability to new attack vectors. The SBSEC 2026 extension validates this approach on a broader attack surface. Planned future work includes:

- Validation on larger and more diverse datasets
- Comparison against classical ML-based IDS approaches
- Integration with real programmable switch hardware (P4/OpenFlow)
- Automated rule update cycles when new attack patterns are discovered

---

## References

- IEC 61850-8-1: *Communication networks and systems in substations*, IEC, 2003.
- Hong, J. & Liu, C. (2019). Intelligent electronic devices with collaborative intrusion detection systems. *IEEE Transactions on Smart Grid*, 10(1):271–281.
- Hong, J., Liu, C., & Govindarasu, M. (2014). Detection of cyber intrusions using network-based multicast messages for substation automation. *ISGT, IEEE*.
- Quincozes, S. E. et al. ERENO–IEC–61850 dataset.

---

## Citation

If you use this work, please cite the corresponding paper published at **SBSEC 2026**.
