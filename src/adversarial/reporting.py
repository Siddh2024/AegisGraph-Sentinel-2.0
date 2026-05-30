"""
Report writers: turn a list of EvaluationResults into persisted JSON and
Markdown summaries.

JSON is the machine-readable form (full numerical precision, suitable for
downstream analysis or MLflow ingestion). Markdown is the human-readable
summary intended for PRs, READMEs, and issue comments.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Union

from .evaluator import EvaluationResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json_report(results: Iterable[EvaluationResult], path: Union[Path, str]) -> Path:
    """Write all results to a JSON file. Returns the path written to."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "generated_at": _utc_now_iso(),
        "results": [asdict(r) for r in results],
    }
    with path.open("w") as f:
        json.dump(data, f, indent=2)
    return path


def write_markdown_report(results: Iterable[EvaluationResult], path: Union[Path, str]) -> Path:
    """Write a Markdown summary grouped by attack name. Returns the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    results = list(results)

    by_attack: dict[str, List[EvaluationResult]] = {}
    for r in results:
        by_attack.setdefault(r.attack_name, []).append(r)

    lines: List[str] = []
    lines.append("# Adversarial Robustness Evaluation\n\n")
    lines.append(f"Generated: {_utc_now_iso()}\n\n")
    if results:
        lines.append(f"Graphs per (attack, budget): {results[0].n_graphs}\n")
        lines.append(f"Decision threshold: {results[0].threshold}\n")

    for attack_name, rs in by_attack.items():
        lines.append(f"\n## {attack_name}\n\n")
        lines.append("| Budget | Clean (mean ± std) | Attacked (mean ± std) | Delta (mean ± std) | Flip rate |\n")
        lines.append("|---|---|---|---|---|\n")
        for r in sorted(rs, key=lambda x: x.budget):
            lines.append(
                f"| {r.budget:.2%} | "
                f"{r.clean_mean:.4f} ± {r.clean_std:.4f} | "
                f"{r.attacked_mean:.4f} ± {r.attacked_std:.4f} | "
                f"{r.delta_mean:+.4f} ± {r.delta_std:.4f} | "
                f"{r.flip_rate:.1%} |\n"
            )

    with path.open("w") as f:
        f.writelines(lines)
    return path