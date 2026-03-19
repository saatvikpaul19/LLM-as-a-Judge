import json
import os
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, Tuple

import requests


BASE_DIR = Path(__file__).resolve().parent.parent
PROMPT_PATH = BASE_DIR / "prompts" / "judge_prompt.txt"


def load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def build_user_prompt(row: Dict[str, str]) -> str:
    return f"""
Seed sample:
{row['seed_query']}

Candidate sample:
{row['candidate_query']}

Context:
{row['context']}

Syntax validation passed:
{row['syntax_valid']}

Sandbox maliciousness passed:
{row['sandbox_malicious']}

Optional notes:
{row.get('notes', '')}

Return exactly one JSON object that matches the required schema.
Do not return markdown.
Do not return an empty object.
""".strip()


def extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()

    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Model response was not a JSON object.")
        return parsed
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in model response: {text[:400]}")

    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("Extracted JSON was not an object.")
    return parsed


def _is_true_like(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).strip().lower())


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()


def _contains_any(text: str, keywords: list[str]) -> bool:
    t = _normalize(text)
    return any(k in t for k in keywords)


def heuristic_judge(row: Dict[str, str]) -> Tuple[Dict[str, Any], str]:
    seed = row["seed_query"]
    cand = row["candidate_query"]
    context = _normalize(row["context"])
    syntax_ok = _is_true_like(row["syntax_valid"])
    sandbox_ok = _is_true_like(row["sandbox_malicious"])
    joined = _normalize(f"{seed} || {cand} || {row.get('notes', '')}")
    sim = _similarity(seed, cand)

    malicious_intent_preserved = syntax_ok and sandbox_ok and not _contains_any(
        joined,
        ["benign", "harmless", "unrelated", "nonsense", "plain english", "natural language only"],
    )

    realistic_for_context = True
    if _contains_any(joined, ["broken", "malformed", "unbalanced", "random tokens", "nonsense", "unrelated"]):
        realistic_for_context = False
    if context not in {"login", "search", "id_lookup", "admin_panel", "product_filter", "profile_update"}:
        realistic_for_context = False

    non_trivial_mutation = True
    if sim > 0.92:
        non_trivial_mutation = False
    if _contains_any(
        joined,
        ["uppercase only", "spacing only", "punctuation only", "same as seed", "cosmetic only", "case change only"],
    ):
        non_trivial_mutation = False

    score = 5
    if not malicious_intent_preserved:
        score -= 2
    if not realistic_for_context:
        score -= 1
    if not non_trivial_mutation:
        score -= 1
    if sim > 0.97:
        score -= 1
    score = max(1, min(5, score))

    keep = malicious_intent_preserved and realistic_for_context and non_trivial_mutation and score >= 4

    reasons = []
    if malicious_intent_preserved:
        reasons.append("malicious intent appears preserved")
    else:
        reasons.append("malicious intent is not clearly preserved")
    if realistic_for_context:
        reasons.append(f"candidate is plausible for {context}")
    else:
        reasons.append(f"candidate is weak or unrealistic for {context}")
    if non_trivial_mutation:
        reasons.append("mutation is meaningfully different from the seed")
    else:
        reasons.append("mutation looks mostly cosmetic")

    result = {
        "malicious_intent_preserved": malicious_intent_preserved,
        "realistic_for_context": realistic_for_context,
        "non_trivial_mutation": non_trivial_mutation,
        "overall_quality_score": score,
        "keep": keep,
        "reason": "; ".join(reasons) + ".",
    }
    return result, "heuristic"


def ollama_local_generate(system_prompt: str, user_prompt: str) -> str:
    model = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")
    url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")

    judge_schema = {
        "type": "object",
        "properties": {
            "malicious_intent_preserved": {"type": "boolean"},
            "realistic_for_context": {"type": "boolean"},
            "non_trivial_mutation": {"type": "boolean"},
            "overall_quality_score": {"type": "integer", "minimum": 1, "maximum": 5},
            "keep": {"type": "boolean"},
            "reason": {"type": "string"}
        },
        "required": [
            "malicious_intent_preserved",
            "realistic_for_context",
            "non_trivial_mutation",
            "overall_quality_score",
            "keep",
            "reason"
        ]
    }

    grounded_prompt = (
        system_prompt
        + "\n\nYou must return exactly one JSON object matching this schema:\n"
        + json.dumps(judge_schema, indent=2)
        + "\n\n"
        + user_prompt
    )

    payload = {
        "model": model,
        "system": "You are a strict JSON generator. Return only one JSON object.",
        "prompt": grounded_prompt,
        "format": judge_schema,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 220
        }
    }

    response = requests.post(url, json=payload, timeout=240)
    response.raise_for_status()
    data = response.json()

    if "response" not in data:
        raise ValueError(f"Unexpected Ollama response: {data}")

    text = data["response"].strip()
    if not text:
        raise ValueError(f"Empty Ollama response. Full payload: {data}")

    return text


def apply_hard_rules(row: Dict[str, str], parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic overrides to make the judge stricter and more aligned
    with the project rubric.
    """
    seed = row["seed_query"]
    cand = row["candidate_query"]
    notes = _normalize(row.get("notes", ""))
    context = _normalize(row.get("context", ""))
    syntax_ok = _is_true_like(row.get("syntax_valid", "false"))
    sandbox_ok = _is_true_like(row.get("sandbox_malicious", "false"))
    sim = _similarity(seed, cand)

    result = dict(parsed)

    # normalize missing fields if model output is weak
    result.setdefault("malicious_intent_preserved", False)
    result.setdefault("realistic_for_context", False)
    result.setdefault("non_trivial_mutation", False)
    result.setdefault("overall_quality_score", 1)
    result.setdefault("keep", False)
    result.setdefault("reason", "No reason provided.")

    reason_parts = [str(result["reason"]).strip()]

    # rule 1: if syntax or sandbox failed, cannot keep
    if not syntax_ok or not sandbox_ok:
        result["malicious_intent_preserved"] = False
        result["keep"] = False
        result["overall_quality_score"] = min(int(result["overall_quality_score"]), 2)
        reason_parts.append("Rejected by hard rule because syntax_valid or sandbox_malicious is false.")

    # rule 2: trivial mutation notes force rejection
    trivial_keywords = [
        "uppercase only",
        "lowercase only",
        "spacing only",
        "punctuation only",
        "same as seed",
        "cosmetic only",
        "case change only",
        "formatting-only rewrite",
        "case-only rewrite",
    ]
    if _contains_any(notes, trivial_keywords):
        result["non_trivial_mutation"] = False
        result["keep"] = False
        result["overall_quality_score"] = min(int(result["overall_quality_score"]), 2)
        reason_parts.append("Rejected by hard rule because notes indicate a trivial mutation.")

    # rule 3: very high similarity also forces trivial
    if sim >= 0.93:
        result["non_trivial_mutation"] = False
        result["keep"] = False
        result["overall_quality_score"] = min(int(result["overall_quality_score"]), 2)
        reason_parts.append(f"Rejected by hard rule because seed/candidate similarity is too high ({sim:.2f}).")

    # rule 4: unrealistic/broken notes force realism false
    unrealistic_keywords = [
        "broken",
        "malformed",
        "unbalanced",
        "random tokens",
        "nonsense",
        "unrelated",
        "plain english",
        "natural language only",
        "payload_inside_quotes_only",
        "not_effectively_malicious",
        "parse_failed",
    ]
    if _contains_any(notes, unrealistic_keywords):
        result["realistic_for_context"] = False
        result["keep"] = False
        result["overall_quality_score"] = min(int(result["overall_quality_score"]), 2)
        reason_parts.append("Rejected by hard rule because notes indicate unrealistic or broken content.")

    # rule 5: unknown context is suspicious
    allowed_contexts = {"login", "search", "id_lookup", "admin_panel", "product_filter", "profile_update"}
    if context not in allowed_contexts:
        result["realistic_for_context"] = False
        result["keep"] = False
        result["overall_quality_score"] = min(int(result["overall_quality_score"]), 2)
        reason_parts.append("Rejected by hard rule because context is outside the allowed task contexts.")

    # final keep rule
    result["keep"] = (
        bool(result["malicious_intent_preserved"])
        and bool(result["realistic_for_context"])
        and bool(result["non_trivial_mutation"])
        and int(result["overall_quality_score"]) >= 4
    )

    result["reason"] = " ".join(p for p in reason_parts if p)
    return result