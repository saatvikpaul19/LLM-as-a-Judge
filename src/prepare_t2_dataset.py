import json
from pathlib import Path

import pandas as pd
import sqlglot


BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_PATH = BASE_DIR / "data" / "generated_payloads.csv"
OUTPUT_PATH = BASE_DIR / "data" / "generated_payloads_prepared.csv"


def safe_parse_sql(query: str):
    try:
        parsed = sqlglot.parse_one(str(query))
        return True, parsed
    except Exception:
        return False, None


def extract_node_names(parsed) -> list[str]:
    if parsed is None:
        return []
    return sorted({node.__class__.__name__ for node in parsed.walk()})


def payload_inside_quotes_only(payload: str, full_query: str) -> bool:
    payload = str(payload)
    full_query = str(full_query).lower()
    checks = [
        f"'{payload.lower()}'",
        f'"{payload.lower()}"',
        f"%{payload.lower()}%",
        f"like '%{payload.lower()}%'",
    ]
    return any(check in full_query for check in checks)


def derive_sandbox_fields(payload: str, full_query: str, attack_category: str, ast_is_valid: bool):
    payload_l = str(payload).lower()
    full_query_l = str(full_query).lower()
    category_l = str(attack_category).lower()

    if not ast_is_valid:
        return False, "ast_invalid", ""

    if payload_inside_quotes_only(payload, full_query):
        return False, "quoted_only", ""

    category_to_exploit = {
        "tautology": "tautology",
        "union_based": "union_based",
        "blind_boolean": "blind_boolean",
        "blind_time": "blind_time",
        "stacked_queries": "stacked_queries",
        "comment_obfuscation": "comment_obfuscation",
        "encoding_obfuscation": "encoding_obfuscation",
        "nested_injection": "nested_injection",
    }

    suspicious_markers = [
        " or ",
        " and ",
        " union ",
        "--",
        "/*",
        "*/",
        ";",
        "sleep(",
        "benchmark(",
        "waitfor",
        "information_schema",
        "drop table",
        "xp_cmdshell",
    ]

    sandbox_pass = any(marker in payload_l or marker in full_query_l for marker in suspicious_markers)
    exploit_type = category_to_exploit.get(category_l, category_l if sandbox_pass else "")
    detection_mode = "complete_query" if sandbox_pass else "no_exploit"

    return sandbox_pass, detection_mode, exploit_type


def main():
    df = pd.read_csv(INPUT_PATH)
    if "label" in df.columns:
        df = df[df["label"] == 1].copy()

    has_real_sandbox = {
        "sandbox_executed",
        "sandbox_detection_mode",
        "sandbox_exploit_type",
    }.issubset(df.columns)

    rows = []
    for idx, row in df.iterrows():
        query_id = f"q{idx:05d}"
        payload = str(row["payload"])
        full_query = str(row.get("full_query", ""))
        attack_category = str(row.get("attack_category", row.get("llm_attack_category", "unknown")))
        template_context = str(row.get("template_context", "search"))

        ast_is_valid, parsed = safe_parse_sql(full_query)
        ast_node_set = extract_node_names(parsed)

        if has_real_sandbox:
            sandbox_executed = str(row["sandbox_executed"]).strip().lower() in {"true", "1", "yes", "y"}
            sandbox_detection_mode = str(row["sandbox_detection_mode"])
            sandbox_exploit_type = str(row["sandbox_exploit_type"])
            sandbox_source = "upstream_real"
        else:
            sandbox_executed, sandbox_detection_mode, sandbox_exploit_type = derive_sandbox_fields(
                payload=payload,
                full_query=full_query,
                attack_category=attack_category,
                ast_is_valid=ast_is_valid,
            )
            sandbox_source = "heuristic_proxy"

        notes = []
        if payload_inside_quotes_only(payload, full_query):
            notes.append("payload_inside_quotes_only")
        if not ast_is_valid:
            notes.append("parse_failed")
        if not sandbox_executed:
            notes.append("not_effectively_malicious")

        out_row = {
            "query_id": query_id,
            "payload": payload,
            "full_query": full_query,
            "attack_category": attack_category,
            "template_context": template_context,
            "label": 1,
            "mutation_count": 1,
            "codebert_score": 0.0,
            "ast_is_valid": ast_is_valid,
            "ast_dialect": "default",
            "ast_node_set": json.dumps(ast_node_set, ensure_ascii=False),
            "sandbox_executed": sandbox_executed,
            "sandbox_detection_mode": sandbox_detection_mode,
            "sandbox_exploit_type": sandbox_exploit_type,
            "sandbox_source": sandbox_source,
            "notes": "; ".join(notes),
        }

        if "seed_payload" in row and pd.notna(row.get("seed_payload")):
            out_row["seed_payload"] = str(row.get("seed_payload"))
        elif "seed_query" in row and pd.notna(row.get("seed_query")):
            out_row["seed_payload"] = str(row.get("seed_query"))

        rows.append(out_row)

    out = pd.DataFrame(rows)
    out.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved {len(out)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()