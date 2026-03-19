# LLM-as-a-Judge — SQL Injection Adversarial Filter

## Overview

This module implements the **LLM-as-a-Judge** component of a SQL injection adversarial robustness pipeline.

It reads candidate SQL injection samples from CSV files and decides whether each sample should be **kept** in the synthetic adversarial dataset or **rejected** as trivial, weak, malformed, unrealistic, or insufficiently malicious.

The module runs entirely locally — no paid APIs required.

---

## How It Works

The judge uses a **hybrid design** to avoid blindly trusting the LLM:

1. **LLM semantic judgment** — a local Qwen model (via Ollama) evaluates each candidate
2. **Deterministic hard-rule overrides** — post-processing rules catch cases the LLM may miss

### What Each Candidate Is Evaluated On

| Field | Description |
|---|---|
| `malicious_intent_preserved` | Does the mutation retain the original attack intent? |
| `realistic_for_context` | Would this payload appear in a real attack scenario? |
| `non_trivial_mutation` | Is this meaningfully different from the seed query? |
| `overall_quality_score` | Composite quality rating |
| `keep` | Final keep/reject decision |

### Hard-Rule Rejection Triggers

A sample is automatically rejected if any of the following are detected:

- `uppercase_only` — mutation is purely a case change
- `spacing_only` — mutation only alters whitespace
- `punctuation_only` — mutation only alters punctuation
- `same_as_seed` — identical to the original query
- `cosmetic_only` — surface-level change with no semantic effect
- `parse_failed` — query does not parse as valid SQL
- `payload_inside_quotes_only` — payload is neutralised inside a string literal
- `not_effectively_malicious` — no meaningful SQL injection signal detected

---

## Folder Structure
```text
LLM_JUDGE/
├── .venv/
├── data/
│   ├── generated_payloads.csv          # Raw T2 teammate dataset
│   ├── judge_samples_from_t2.csv       # Converted input for the judge
│   └── judge_results_from_t2.csv       # Final keep/reject decisions
├── prompts/
│   └── judge_prompt.txt
├── src/
│   ├── evaluate_judge.py
│   ├── judge_schema.py
│   ├── prepare_t2_dataset.py           # Converts T2 dataset to judge format
│   ├── run_judge.py                    # Main judge runner
│   └── utils.py
├── .env
├── .env.example
├── README.md
└── requirements.txt
```

---

## Setup

### 1. Create and activate the virtual environment
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies
```powershell
pip install -r requirements.txt
pip install sqlglot
```

**`requirements.txt`**
```
pandas
pydantic>=2.6.0
python-dotenv
requests
tqdm
sqlglot
```

### 3. Set up Ollama

Verify Ollama is installed:
```powershell
ollama --version
```

Pull the Qwen model:
```powershell
ollama pull qwen3:1.7b
ollama list
```

**Optional — quick smoke test:**
```powershell
ollama run qwen3:1.7b
```
Then type the following and verify you get back valid JSON:
```
Return exactly this JSON and nothing else:
{"ok": true}
```
Exit with `/bye`.

### 4. Configure `.env`

Create a `.env` file in the project root:
```env
OLLAMA_MODEL=qwen3:1.7b
OLLAMA_URL=http://localhost:11434/api/generate
```

---

## Running the Pipeline

### Step 1 — Prepare the T2 dataset

The raw teammate-provided dataset (`data/generated_payloads.csv`) must be converted to the judge's expected schema before running.

`prepare_t2_dataset.py` handles:
- Context normalisation
- SQL parsing via `sqlglot`
- Approximate maliciousness detection
- Note generation for deterministic filtering
```powershell
$env:PYTHONPATH="src"
python src/prepare_t2_dataset.py
```

Expected output:
```
Saved 119 rows to E:\llm_judge\data\judge_samples_from_t2.csv

Derived stats:
syntax_valid=true:  56
syntax_valid=false: 63
sandbox_malicious=true:  4
sandbox_malicious=false: 115
```

### Step 2 — Run the judge
```powershell
$env:PYTHONPATH="src"
python src/run_judge.py \
  --backend ollama_local \
  --input  data/judge_samples_from_t2.csv \
  --output data/judge_results_from_t2.csv \
  --errors data/judge_errors_from_t2.csv
```

Outputs:
- `data/judge_results_from_t2.csv` — all judged rows with decisions
- `data/judge_errors_from_t2.csv` — any rows that failed processing

---

## Inspecting Results

**Summary counts:**
```powershell
python -c "
import pandas as pd
df = pd.read_csv('data/judge_results_from_t2.csv')
print('Total judged:', len(df))
print('Accepted:    ', int(df['keep'].sum()))
print('Rejected:    ', int((~df['keep']).sum()))
"
```

**Preview the first 10 rows:**
```powershell
Get-Content .\data\judge_results_from_t2.csv | Select-Object -First 10
```

**Inspect failed rows:**
```powershell
Import-Csv .\data\judge_errors_from_t2.csv | Format-List
```

**Print accepted rows:**
```powershell
python -c "
import pandas as pd
df = pd.read_csv('data/judge_results_from_t2.csv')
cols = ['id', 'context', 'seed_query', 'candidate_query', 'reason']
print(df[df['keep'] == True][cols].to_string(index=False))
"
```

**Print a sample of rejected rows:**
```powershell
python -c "
import pandas as pd
df = pd.read_csv('data/judge_results_from_t2.csv')
cols = ['id', 'context', 'seed_query', 'candidate_query', 'reason']
print(df[df['keep'] == False][cols].head(15).to_string(index=False))
"
```

---

## Full Command Sequence
```powershell
& e:\llm_judge\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="src"
python src/prepare_t2_dataset.py
python src/run_judge.py --backend ollama_local --input data/judge_samples_from_t2.csv --output data/judge_results_from_t2.csv --errors data/judge_errors_from_t2.csv
python -c "import pandas as pd; df=pd.read_csv('data/judge_results_from_t2.csv'); print('Total:', len(df)); print('Accepted:', int(df['keep'].sum())); print('Rejected:', int((~df['keep']).sum()))"
```

---

## Current Results (T2 Dataset Integration)

| Metric | Count |
|---|---|
| Total rows processed | 119 |
| SQL parse valid | 56 |
| SQL parse invalid | 63 |
| Effectively malicious | 4 |
| Not effectively malicious | 115 |
| Runtime errors | 0 |
| **Accepted** | **4** |
| **Rejected** | **115** |

The judge functions as a genuine filter rather than a rubber stamp — only samples that pass both semantic and deterministic checks are kept.

---

## Validation Details

### SQL Parsing
Uses `sqlglot.parse_one(full_query)` to determine syntactic validity.

### Approximate Maliciousness Detection
A row is flagged as not effectively malicious if:
- the query fails to parse
- the payload is neutralised inside quotes
- the query lacks sufficient SQL injection signal

### Hard-Rule Overrides
Even when the LLM is too permissive, deterministic post-processing rejects rows where notes indicate trivial mutations, parse failures, trapped payloads, or ineffective injection attempts.

---

## Integration Points

This module is designed to slot into the broader adversarial pipeline alongside:

- **T1/T2 generators** — upstream sample producers
- **Syntax validator** — SQL parse checking
- **Sandbox validator** — runtime maliciousness testing
- **Adversarial training pipeline** — downstream consumer of accepted samples