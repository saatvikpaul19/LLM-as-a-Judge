from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
ACCEPTED_PATH = BASE_DIR / "data" / "adversarial_dataset.csv"
REJECTED_PATH = BASE_DIR / "data" / "mutation_queue.json"
OUTPUT_PATH = BASE_DIR / "data" / "t3_metrics_summary.md"


def load_rejected(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("mutation_queue.json must contain a JSON list.")
    return data


def counts_to_lines(series: pd.Series) -> list[str]:
    if series.empty:
        return ["- none: 0"]
    return [f"- {idx}: {int(val)}" for idx, val in series.items()]


def main():
    if not ACCEPTED_PATH.exists():
        raise FileNotFoundError(f"Accepted dataset not found: {ACCEPTED_PATH}")
    if not REJECTED_PATH.exists():
        raise FileNotFoundError(f"Rejected queue not found: {REJECTED_PATH}")

    accepted_df = pd.read_csv(ACCEPTED_PATH)
    rejected_rows = load_rejected(REJECTED_PATH)
    rejected_df = pd.DataFrame(rejected_rows)

    accepted_count = len(accepted_df)
    rejected_count = len(rejected_rows)
    total_count = accepted_count + rejected_count
    acceptance_rate = (accepted_count / total_count * 100) if total_count else 0.0

    accepted_context = (
        accepted_df["template_context"]
        .fillna("unknown")
        .astype(str)
        .value_counts()
    )

    accepted_attack = (
        accepted_df["llm_attack_category"]
        .fillna("unknown")
        .astype(str)
        .value_counts()
    )

    if "sandbox_exploit_type" in accepted_df.columns:
        accepted_sandbox = (
            accepted_df["sandbox_exploit_type"]
            .fillna("unknown")
            .replace("", "unknown")
            .astype(str)
            .value_counts()
        )
    else:
        accepted_sandbox = pd.Series(dtype="int64")

    if "judge_overall_quality_score" in accepted_df.columns:
        accepted_quality = (
            accepted_df["judge_overall_quality_score"]
            .fillna("unknown")
            .astype(str)
            .value_counts()
            .sort_index()
        )
    else:
        accepted_quality = pd.Series(dtype="int64")

    if not rejected_df.empty and "failure_stage" in rejected_df.columns:
        rejected_stage = (
            rejected_df["failure_stage"]
            .fillna("unknown")
            .replace("", "unknown")
            .astype(str)
            .value_counts()
        )
    else:
        rejected_stage = pd.Series(dtype="int64")

    if not rejected_df.empty and "template_context" in rejected_df.columns:
        rejected_context = (
            rejected_df["template_context"]
            .fillna("unknown")
            .replace("", "unknown")
            .astype(str)
            .value_counts()
        )
    else:
        rejected_context = pd.Series(dtype="int64")

    lines = []
    lines.append("# T3 Metrics Summary")
    lines.append("")
    lines.append("## Final accepted dataset summary")
    lines.append(f"- Accepted dataset file: `{ACCEPTED_PATH.name}`")
    lines.append(f"- Total accepted adversarial queries: **{accepted_count}**")
    lines.append(f"- Total rejected candidates: **{rejected_count}**")
    lines.append(f"- End-to-end acceptance rate: **{acceptance_rate:.2f}%**")
    lines.append("")
    lines.append("## Accepted context breakdown")
    lines.extend(counts_to_lines(accepted_context))
    lines.append("")
    lines.append("## Accepted attack-category breakdown")
    lines.extend(counts_to_lines(accepted_attack))
    lines.append("")
    lines.append("## Accepted sandbox exploit-type breakdown")
    lines.extend(counts_to_lines(accepted_sandbox))
    lines.append("")
    lines.append("## Judge quality-score distribution")
    lines.extend(counts_to_lines(accepted_quality))
    lines.append("")
    lines.append("## Rejected failure-stage breakdown")
    lines.extend(counts_to_lines(rejected_stage))
    lines.append("")
    lines.append("## Rejected context breakdown")
    lines.extend(counts_to_lines(rejected_context))
    lines.append("")
    lines.append("## Notes")
    lines.append("- `label` should remain `1` for all final malicious samples.")
    lines.append("- The final accepted dataset should only contain the project-supported contexts for retraining.")
    lines.append("- Use this file together with `adversarial_dataset.csv` when handing metrics to the retraining / analysis owner.")

    output_text = "\n".join(lines)
    OUTPUT_PATH.write_text(output_text, encoding="utf-8")
    print(output_text)


if __name__ == "__main__":
    main()