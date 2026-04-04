import argparse
import json
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from tqdm import tqdm

from judge_schema import JudgeResult
from utils import (
    apply_hard_rules,
    build_user_prompt,
    extract_json,
    heuristic_judge,
    load_system_prompt,
    normalize_candidate_row,
    ollama_local_generate,
    rejection_hint,
    sandbox_failure_reason,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_PATH = BASE_DIR / "data" / "generated_payloads.csv"
ACCEPTED_PATH = BASE_DIR / "data" / "adversarial_dataset.csv"
REJECTED_PATH = BASE_DIR / "data" / "mutation_queue.json"
ALL_RESULTS_PATH = BASE_DIR / "data" / "judge_results.csv"
SUMMARY_PATH = BASE_DIR / "data" / "judge_summary.txt"


FINAL_ACCEPTED_COLUMNS = [
    "query_id",
    "payload",
    "full_query",
    "llm_attack_category",
    "template_context",
    "label",
    "mutation_count",
    "codebert_score",
    "ast_is_valid",
    "ast_dialect",
    "ast_node_set",
    "sandbox_executed",
    "sandbox_detection_mode",
    "sandbox_exploit_type",
    "judge_malicious_intent_preserved",
    "judge_realistic_for_context",
    "judge_non_trivial_mutation",
    "judge_overall_quality_score",
    "judge_reason",
]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["heuristic", "ollama_local"], default="ollama_local")
    parser.add_argument("--input", default=str(INPUT_PATH))
    parser.add_argument("--accepted", default=str(ACCEPTED_PATH))
    parser.add_argument("--rejected", default=str(REJECTED_PATH))
    parser.add_argument("--all-results", default=str(ALL_RESULTS_PATH))
    parser.add_argument("--summary", default=str(SUMMARY_PATH))
    return parser.parse_args()


def _accepted_row(row, result):
    return {
        "query_id": row["query_id"],
        "payload": row["payload"],
        "full_query": row["full_query"],
        "llm_attack_category": row["llm_attack_category"],
        "template_context": row["template_context"],
        "label": row["label"],
        "mutation_count": row["mutation_count"],
        "codebert_score": row["codebert_score"],
        "ast_is_valid": row["ast_is_valid"],
        "ast_dialect": row["ast_dialect"],
        "ast_node_set": row["ast_node_set"],
        "sandbox_executed": row["sandbox_executed"],
        "sandbox_detection_mode": row["sandbox_detection_mode"],
        "sandbox_exploit_type": row["sandbox_exploit_type"],
        "judge_malicious_intent_preserved": result.malicious_intent_preserved,
        "judge_realistic_for_context": result.realistic_for_context,
        "judge_non_trivial_mutation": result.non_trivial_mutation,
        "judge_overall_quality_score": result.overall_quality_score,
        "judge_reason": result.reason,
    }


def _reject_row(row, stage, reason):
    reject = {
        "query_id": row["query_id"],
        "payload": row["payload"],
        "full_query": row["full_query"],
        "attack_category": row["llm_attack_category"],
        "template_context": row["template_context"],
        "failure_stage": stage,
        "failure_reason": reason,
        "codebert_score": row["codebert_score"],
        "mutation_count": row["mutation_count"],
        "hint": rejection_hint(stage),
    }
    if row.get("seed_payload_available"):
        reject["seed_payload"] = row["seed_payload"]
    return reject


def _all_result_row(row, parsed, backend_used, status):
    out = {
        "query_id": row["query_id"],
        "payload": row["payload"],
        "full_query": row["full_query"],
        "llm_attack_category": row["llm_attack_category"],
        "template_context": row["template_context"],
        "label": row["label"],
        "mutation_count": row["mutation_count"],
        "codebert_score": row["codebert_score"],
        "ast_is_valid": row["ast_is_valid"],
        "ast_dialect": row["ast_dialect"],
        "ast_node_set": row["ast_node_set"],
        "sandbox_executed": row["sandbox_executed"],
        "sandbox_detection_mode": row["sandbox_detection_mode"],
        "sandbox_exploit_type": row["sandbox_exploit_type"],
        "judge_malicious_intent_preserved": parsed["malicious_intent_preserved"],
        "judge_realistic_for_context": parsed["realistic_for_context"],
        "judge_non_trivial_mutation": parsed["non_trivial_mutation"],
        "judge_overall_quality_score": parsed["overall_quality_score"],
        "judge_keep": parsed["keep"],
        "judge_reason": parsed["reason"],
        "backend": backend_used,
        "status": status,
    }
    if row.get("seed_payload_available"):
        out["seed_payload"] = row["seed_payload"]
    return out


def main():
    args = parse_args()
    system_prompt = load_system_prompt()

    input_path = Path(args.input)
    accepted_path = Path(args.accepted)
    rejected_path = Path(args.rejected)
    all_results_path = Path(args.all_results)
    summary_path = Path(args.summary)

    df = pd.read_csv(input_path, dtype=str).fillna("")
    rows = [normalize_candidate_row(record) for record in df.to_dict(orient="records")]

    accepted_rows = []
    rejected_rows = []
    all_rows = []
    errors = []

    for row in tqdm(rows, desc="Judging candidates"):
        try:
            if row["existing_failure_stage"] and row["existing_failure_reason"]:
                stage = row["existing_failure_stage"]
                reason = row["existing_failure_reason"]
                rejected_rows.append(_reject_row(row, stage, reason))
                continue

            if not row["ast_is_valid"] or not row["sandbox_executed"]:
                stage = "sandbox"
                reason = sandbox_failure_reason(row)
                rejected_rows.append(_reject_row(row, stage, reason))
                heuristic_result, backend_used = heuristic_judge(row)
                heuristic_result = apply_hard_rules(row, heuristic_result)
                all_rows.append(_all_result_row(row, heuristic_result, backend_used, "rejected_pre_judge"))
                continue

            if args.backend == "heuristic":
                parsed, backend_used = heuristic_judge(row)
                parsed = apply_hard_rules(row, parsed)
            else:
                user_prompt = build_user_prompt(row)
                try:
                    raw_response = ollama_local_generate(system_prompt, user_prompt)
                    parsed = extract_json(raw_response)
                    parsed = apply_hard_rules(row, parsed)
                    backend_used = "ollama_local+rules"
                except Exception:
                    parsed, _ = heuristic_judge(row)
                    parsed = apply_hard_rules(row, parsed)
                    backend_used = "heuristic_fallback+rules"

            result = JudgeResult(**parsed)
            all_rows.append(_all_result_row(row, parsed, backend_used, "ok"))

            if result.keep:
                accepted_rows.append(_accepted_row(row, result))
            else:
                rejected_rows.append(_reject_row(row, "judge", f"Judge rejected: {result.reason}"))

        except Exception as exc:
            errors.append({"query_id": row.get("query_id", ""), "error": str(exc)})
            rejected_rows.append(
                _reject_row(
                    row,
                    "judge",
                    f"Judge failed to process the candidate cleanly. Error: {exc}",
                )
            )

    accepted_df = pd.DataFrame(accepted_rows, columns=FINAL_ACCEPTED_COLUMNS)
    all_results_df = pd.DataFrame(all_rows)

    accepted_path.parent.mkdir(parents=True, exist_ok=True)
    rejected_path.parent.mkdir(parents=True, exist_ok=True)
    all_results_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    accepted_df.to_csv(accepted_path, index=False)

    with rejected_path.open("w", encoding="utf-8") as handle:
        json.dump(rejected_rows, handle, indent=2, ensure_ascii=False)

    if not all_results_df.empty:
        all_results_df.to_csv(all_results_path, index=False)

    accepted_count = len(accepted_rows)
    rejected_count = len(rejected_rows)
    total_count = accepted_count + rejected_count
    judge_reject_count = sum(1 for row in rejected_rows if row["failure_stage"] == "judge")
    sandbox_reject_count = sum(1 for row in rejected_rows if row["failure_stage"] == "sandbox")

    lines = [
        f"Input rows: {len(rows)}",
        f"Accepted rows: {accepted_count}",
        f"Rejected rows: {rejected_count}",
        f"Acceptance rate: {(accepted_count / total_count):.2%}" if total_count else "Acceptance rate: 0.00%",
        f"Judge-stage rejects: {judge_reject_count}",
        f"Sandbox-stage rejects: {sandbox_reject_count}",
        f"Accepted dataset: {accepted_path}",
        f"Rejected queue: {rejected_path}",
        f"Full judge results: {all_results_path}",
        f"Errors captured: {len(errors)}",
    ]
    summary_text = "\n".join(lines)
    summary_path.write_text(summary_text, encoding="utf-8")

    print(summary_text)
    if errors:
        print("\nSome rows produced exceptions and were pushed to the reject queue.")


if __name__ == "__main__":
    main()