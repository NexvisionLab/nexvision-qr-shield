from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.analyzer import analyze_payload

POSITIVE_VERDICTS = {"Suspicious", "High risk", "Dangerous"}


async def evaluate(path: Path) -> dict:
    matrix = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "abstain": 0}
    by_region: dict[str, dict[str, int]] = {}
    failures = []
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for index, record in enumerate(records, 1):
        result = await analyze_payload(record["payload"], network_checks=False)
        expected = record["label"] == "malicious"
        predicted = result.verdict in POSITIVE_VERDICTS
        if result.verdict == "Unable to determine":
            matrix["abstain"] += 1
        elif expected and predicted: matrix["tp"] += 1
        elif not expected and not predicted: matrix["tn"] += 1
        elif predicted: matrix["fp"] += 1
        else: matrix["fn"] += 1
        region = record.get("region", "unspecified")
        bucket = by_region.setdefault(region, {key: 0 for key in matrix})
        if result.verdict == "Unable to determine": bucket["abstain"] += 1
        elif expected and predicted: bucket["tp"] += 1
        elif not expected and not predicted: bucket["tn"] += 1
        elif predicted: bucket["fp"] += 1
        else: bucket["fn"] += 1
        if (expected != predicted) and result.verdict != "Unable to determine":
            failures.append({"record": index, "id": record.get("id"), "expected": record["label"], "verdict": result.verdict, "score": result.score})
    classified = matrix["tp"] + matrix["tn"] + matrix["fp"] + matrix["fn"]
    return {
        "corpus": str(path), "records": len(records), "matrix": matrix,
        "precision": round(matrix["tp"] / max(1, matrix["tp"] + matrix["fp"]), 4),
        "recall": round(matrix["tp"] / max(1, matrix["tp"] + matrix["fn"]), 4),
        "false_positive_rate": round(matrix["fp"] / max(1, matrix["fp"] + matrix["tn"]), 4),
        "abstention_rate": round(matrix["abstain"] / max(1, len(records)), 4),
        "classified_records": classified, "by_region": by_region, "failures": failures,
        "warning": "Metrics are only meaningful for an independently sourced, legally usable, time-separated corpus. Do not use the bundled synthetic smoke corpus for product claims.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = asyncio.run(evaluate(args.corpus))
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output: args.output.write_text(rendered, encoding="utf-8")
    else: print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
