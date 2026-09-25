from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .analyzer import analyze_payload
from .artifact import decode_artifact
from .decoder import DecodeError


async def _run(args) -> int:
    if args.file:
        path = Path(args.file)
        try:
            decoded = decode_artifact(path.read_bytes(), path.name)
        except (OSError, DecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        results = [await analyze_payload(item["payload"], item["sha256"], False, item["image_analysis"], item["context_text"]) for item in decoded]
        output = {"count": len(results), "results": [item.to_dict() for item in results]}
    else:
        output = (await analyze_payload(args.text, network_checks=False)).to_dict()
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline NexVision QR Shield analyzer")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", "--image", dest="file", help="Path to a QR image, PDF or EML file")
    source.add_argument("--text", help="Already-decoded QR payload")
    return asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
