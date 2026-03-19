import argparse
import csv
from pathlib import Path

from dotenv import load_dotenv
from tqdm import tqdm

from judge_schema import JudgeResult
from utils import (
    apply_hard_rules,
    build_user_prompt,
    extract_json,
    heuristic_judge,
    load_system_prompt,
    ollama_local_generate,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "judge_samples.csv"
OUT_PATH = BASE_DIR / "data" / "judge_results.csv"
ERROR_PATH = BASE_DIR / "data" / "judge_errors.csv"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["heuristic", "ollama_local"], default="heuristic")
    parser.add_argument("--input", default=str(DATA_PATH))
    parser.add_argument("--output", default=str(OUT_PATH))
    parser.add_argument("--errors", default=str(ERROR_PATH))
    return parser.parse_args()


def main():
    args = parse_args()
    system_prompt = load_system_prompt()

    input_path = Path(args.input)
    output_path = Path(args.output)
    error_path = Path(args.errors)

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    results = []
    errors = []

    for row in tqdm(rows, desc="Judging samples"):
        try:
            if args.backend == "heuristic":
                parsed, backend_used = heuristic_judge(row)
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
            results.append(
                {
                    **row,
                    "malicious_intent_preserved": result.malicious_intent_preserved,
                    "realistic_for_context": result.realistic_for_context,
                    "non_trivial_mutation": result.non_trivial_mutation,
                    "overall_quality_score": result.overall_quality_score,
                    "keep": result.keep,
                    "reason": result.reason,
                    "backend": backend_used,
                    "status": "ok",
                }
            )
        except Exception as e:
            errors.append({**row, "error": str(e)})

    if output_path.exists():
        output_path.unlink()
    if error_path.exists():
        error_path.unlink()

    if results:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)

    if errors:
        with open(error_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(errors[0].keys()))
            writer.writeheader()
            writer.writerows(errors)

    print(f"Saved ok rows: {len(results)} -> {output_path}")
    print(f"Saved error rows: {len(errors)} -> {error_path}")


if __name__ == "__main__":
    main()