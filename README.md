# LLM-as-a-Judge for SQL Injection Candidate Filtering

## Project purpose

This component implements the **LLM-as-a-Judge** stage of an adversarial SQL injection pipeline.

The goal is **not** to generate SQL injection attacks.
The goal is to take one CSV file of candidate SQL injection samples, judge each candidate query, and split the file into:

* an **accepted CSV** containing strong candidates that should be kept in the final synthetic dataset
* a **rejected CSV** containing weak, unrealistic, unsupported, or invalid candidates

It also generates:

* a **full judge results CSV**
* a **judge run summary**
* a **T3 metrics summary** with acceptance/rejection analysis

This judge is designed to run after candidate SQL injection payloads have already been generated and, ideally, validated with AST and sandbox signals. If those signals are present in the input CSV, the judge uses them directly as part of the final decision.

---

## High-level workflow

The workflow is:

1. A CSV of candidate SQL injection samples is provided as input.
2. The repository reads that CSV.
3. Each row is normalized into a standard internal format.
4. The judge evaluates each row using **Ollama**.
5. The judge decides whether the query should be **kept** or **rejected**.
6. The script writes:

   * `accepted_candidates.csv`
   * `rejected_candidates.csv`
   * `judge_results.csv`
   * `judge_summary.txt`
7. A second script creates a Markdown summary with statistics and analysis:

   * `t3_metrics_summary.md`

---

## What the LLM judge actually does

The LLM judge evaluates each candidate with a fixed rubric.

It checks these criteria:

### 1. `malicious_intent_preserved`

This asks:

* Does the candidate still behave like a SQL injection attempt?
* Is it still malicious in intent?
* Has it become harmless, broken, neutralized, or meaningless?

A candidate should be rejected on this criterion if it is:

* benign
* broken
* neutralized inside quotes
* unrelated to SQL injection
* no longer meaningfully malicious

---

### 2. `realistic_for_context`

This asks:

* Is the candidate plausible for the application context it appears in?

For this project, the final accepted contexts are:

* `login`
* `search`

Any candidate outside the final allowed contexts is rejected by hard rule.

Examples of unsupported contexts include:

* `user_lookup`
* `order_filter`
* `comment_insert`

Even if such a row looks malicious, it is still rejected because it is outside the final scoped dataset.

---

### 3. `non_trivial_mutation`

This asks:

* Is the candidate meaningfully different from the seed payload?

If a seed payload is available, the judge compares:

* seed payload
* candidate payload

If no seed payload is available, the judge uses a weaker heuristic based on content and notes.

A candidate is considered **trivial** and should be rejected if it is only:

* uppercase only
* lowercase only
* spacing only
* punctuation only
* cosmetic only
* same as seed
* case-only rewrite
* formatting-only rewrite

---

### 4. `overall_quality_score`

The judge gives a score from **1 to 5**:

* `1` = very poor
* `2` = weak
* `3` = borderline
* `4` = good
* `5` = excellent

---

### 5. `keep`

A row is accepted only if **all** of the following are true:

* `malicious_intent_preserved = true`
* `realistic_for_context = true`
* `non_trivial_mutation = true`
* `overall_quality_score >= 4`

Otherwise, the row is rejected.

---

## Hard-rule filtering

Even after the LLM responds, the code applies hard rules.

A candidate is force-rejected if:

* AST validation failed
* sandbox execution failed
* the notes indicate trivial mutation
* seed/candidate similarity is too high
* the notes indicate unrealistic or broken content
* the context is outside the allowed final contexts

This means the LLM does not have complete freedom.
The final decision is a combination of:

* deterministic checks
* LLM judgment
* hard-rule enforcement

---

## Ollama backend

This project uses **Ollama** as the LLM judge backend.

The default backend is:

* `ollama_local`

The code sends a structured prompt to Ollama and requires the model to return **exactly one JSON object** with these fields:

* `malicious_intent_preserved`
* `realistic_for_context`
* `non_trivial_mutation`
* `overall_quality_score`
* `keep`
* `reason`

The current default model in the code is controlled by environment variables and falls back to:

* `qwen3:1.7b`

---

## Input expectations

The script expects **one CSV input file**.

Typical columns supported include:

* `query_id`
* `payload`
* `full_query`
* `llm_attack_category` or `attack_category`
* `template_context` or `context`
* `label`
* `mutation_count`
* `codebert_score`
* `ast_is_valid` or `syntax_valid`
* `sandbox_executed` or `sandbox_malicious`
* `sandbox_detection_mode`
* `sandbox_exploit_type`
* optional `seed_payload`, `original_payload`, `base_payload`, or `seed_query`

The code also supports multiple aliases and will normalize them into a common internal schema.

### Important note about missing validation fields

If the input CSV does **not** contain AST or sandbox fields, the current normalization logic may treat them as passed by default.

That means this repository works best when the input already contains real validation signals.

---

## Repository files

### Core files

* `src/run_judge.py`
  Runs the LLM judge on the input CSV and writes accepted/rejected outputs.

* `src/summarize_t3.py`
  Builds the Markdown analysis summary from the accepted and rejected CSVs.

* `src/evaluate_sota_metrics.py`
  Computes SOTA-style evaluation metrics from **evaluated prediction CSVs**.

* `src/utils.py`
  Normalization, prompting, Ollama request handling, heuristic fallback, and hard-rule logic.

* `src/judge_schema.py`
  Pydantic schema for validating LLM judge output.

* `prompts/judge_prompt.txt`
  Judge rubric prompt used by Ollama.

### Main outputs

* `data/accepted_candidates.csv`
* `data/rejected_candidates.csv`
* `data/judge_results.csv`
* `data/judge_summary.txt`
* `data/t3_metrics_summary.md`

---

## Environment setup

### 1. Open the project folder

```powershell
cd E:\llm_judge
```

### 2. Activate the virtual environment

```powershell
& E:\llm_judge\.venv\Scripts\Activate.ps1
```

### 3. Install requirements

```powershell
python -m pip install -r requirements.txt
```

### 4. Set the Python path

```powershell
$env:PYTHONPATH="src"
```

---

## Ollama setup

Make sure Ollama is installed and running.

You can verify it with:

```powershell
ollama list
```

If `ollama` is not available in PATH, use the full executable path:

```powershell
& "C:\Users\YOUR_USERNAME\AppData\Local\Programs\Ollama\ollama.exe" list
```

### Recommended environment variables

```powershell
$env:OLLAMA_MODEL="qwen3:1.7b"
$env:OLLAMA_URL="http://localhost:11434/api/generate"
```

---

## How to run the judge

Assume the input file is:

```text
data\adversarial_dataset.csv
```

Run:

```powershell
python src\run_judge.py `
  --backend ollama_local `
  --input data\adversarial_dataset.csv `
  --accepted data\accepted_candidates.csv `
  --rejected data\rejected_candidates.csv `
  --all-results data\judge_results.csv `
  --summary data\judge_summary.txt
```

### What this command does

* reads the input CSV
* evaluates every row with the LLM judge
* writes accepted rows to `accepted_candidates.csv`
* writes rejected rows to `rejected_candidates.csv`
* writes full row-by-row judge output to `judge_results.csv`
* writes a short run summary to `judge_summary.txt`

---

## How to generate the analysis summary

After the judge run finishes, run:

```powershell
python src\summarize_t3.py `
  --accepted data\accepted_candidates.csv `
  --rejected data\rejected_candidates.csv `
  --out data\t3_metrics_summary.md
```

### What this summary contains

* total accepted rows
* total rejected rows
* acceptance rate
* accepted context breakdown
* accepted attack-category breakdown
* accepted judge score distribution
* most common acceptance reasons
* rejected failure-stage breakdown
* rejected context breakdown
* most common rejection reasons
* short interpretation section for reporting

This file is intended to support the **statistics and analysis** section of the project report or slides.

---

## Output file meanings

### `accepted_candidates.csv`

Contains only rows that passed:

* maliciousness preserved
* realism for context
* non-trivial mutation
* score threshold

These are the final rows that should be considered strong enough to keep.

### `rejected_candidates.csv`

Contains rows that were rejected, plus:

* failure stage
* failure reason
* hint

This is the main file for explaining why queries were rejected.

### `judge_results.csv`

Contains the full row-by-row decision data, including:

* candidate information
* judge fields
* backend used
* keep/reject status

### `judge_summary.txt`

Contains a short run summary:

* input rows
* accepted rows
* rejected rows
* acceptance rate
* judge-stage rejects
* sandbox-stage rejects
* output file locations

### `t3_metrics_summary.md`

Contains the final analysis for reporting.

---

## How rejection works in practice

A query can be rejected for at least two broad reasons:

### 1. Deterministic validation failure

Examples:

* AST invalid
* parse failed
* sandbox returned benign
* payload stayed neutralized inside quotes
* no exploit detected

### 2. Judge / hard-rule failure

Examples:

* unsupported context
* unrealistic for the template
* malicious intent not preserved
* trivial mutation
* too close to seed
* broken or nonsensical content

---

## Optional later-stage evaluation metrics

This step is only used if a separate evaluation CSV with model predictions is available. It does **not** run on the candidate CSV used by the LLM judge.

This repository also includes a script for computing standard evaluation metrics:

* Accuracy
* Precision
* Recall
* F1-score
* AUC-ROC
* confusion matrices
* attack success rate
* detection rate

### Required evaluation CSV format

The evaluation script requires a different kind of CSV file that contains at least:

* `label`
* `pred_label`

and ideally:

* `pred_score`

Example:

```csv
label,pred_label,pred_score
1,1,0.98
1,0,0.12
0,0,0.03
0,1,0.88
```

### Run SOTA metrics like this

```powershell
python src\evaluate_sota_metrics.py `
  --input data\generated_eval.csv `
  --name generated_eval `
  --label-col label `
  --pred-col pred_label `
  --score-col pred_score `
  --positive-label 1 `
  --output-dir data\evaluation_outputs
```

### For multiple evaluation splits

```powershell
python src\evaluate_sota_metrics.py `
  --input data\old_test_eval.csv `
  --name old_test `
  --input data\generated_eval.csv `
  --name generated_eval `
  --label-col label `
  --pred-col pred_label `
  --score-col pred_score `
  --positive-label 1 `
  --output-dir data\evaluation_outputs
```

### What this script saves

For each split, it creates a separate folder containing:

* `confusion_matrix.png`
* `confusion_matrix_normalized.png`
* `roc_curve.png` or a placeholder image if unavailable
* `metrics.csv`
* `metrics.json`

It also creates:

* `all_metrics_summary.csv`
* `all_metrics_summary.json`

---

## What this repository does not do

This repository does **not**:

* generate SQL injection payloads
* train CodeBERT
* run a generation pipeline
* produce classifier predictions by itself
* compute SOTA classifier metrics from the candidate CSV alone

Its role is:

* **judge/filter candidate rows**
* **separate accepted and rejected outputs**
* **analyze the filtering results**
* **compute evaluation metrics later only if prediction CSVs are available**

---

## Recommended final workflow

### Step 1

Receive one CSV of candidate SQL injection samples.

### Step 2

Run `run_judge.py` using Ollama.

### Step 3

Produce:

* `accepted_candidates.csv`
* `rejected_candidates.csv`
* `judge_results.csv`
* `judge_summary.txt`

### Step 4

Run `summarize_t3.py` to create:

* `t3_metrics_summary.md`

### Step 5

Only after classifier predictions are available, run:

* `evaluate_sota_metrics.py`

---

## Troubleshooting

### Ollama request fails

Check:

* Ollama is running
* model exists in `ollama list`
* `OLLAMA_URL` is correct
* `OLLAMA_MODEL` is correct

### `pip` is blocked by policy

Use:

```powershell
python -m pip install -r requirements.txt
```

### `ModuleNotFoundError`

Make sure:

```powershell
$env:PYTHONPATH="src"
```

### Accepted output overwrites input

Do not use the same file for:

* `--input`
* `--accepted`

They must be different files.

### SOTA metrics script fails

Check that the evaluation CSV contains:

* `label`
* `pred_label`

and preferably:

* `pred_score`

---

## Summary

This repository implements the **LLM-as-a-Judge** stage of the project.

Its purpose is to:

* read a CSV of candidate SQL injection samples
* evaluate each candidate with Ollama using a strict rubric
* keep only strong candidates
* reject weak ones
* write accepted and rejected CSV outputs
* generate reporting analysis
* optionally compute SOTA evaluation metrics later from prediction CSVs
