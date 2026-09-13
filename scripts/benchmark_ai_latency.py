#!/usr/bin/env python3
"""Benchmark Mongrel's production Ollama client without logging response content."""

import argparse
import json
from pathlib import Path
import sys
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.ai_client import ask_ai, build_mongrel_prompt  # noqa: E402


SHORT_PROMPT = "Reply with one short sentence explaining what Nmap observes."
MEDIUM_PROMPT = build_mongrel_prompt(
    "An authorized web assessment observed ports 80 and 443 and three informational template matches. "
    "Explain what is established, what is not established, and one bounded next step."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warm-calls", type=int, default=3, help="Immediate repeated medium-prompt calls.")
    parser.add_argument("--num-predict", type=int, default=None, help="Optional production output budget override.")
    args = parser.parse_args()

    cases = [("short_first", SHORT_PROMPT), ("medium_first", MEDIUM_PROMPT)]
    cases.extend((f"medium_warm_{index + 1}", MEDIUM_PROMPT) for index in range(max(0, args.warm_calls)))
    for name, prompt in cases:
        captured: list[dict] = []
        started = perf_counter()
        response = ask_ai(
            prompt,
            num_predict=args.num_predict,
            path=f"benchmark.{name}",
            telemetry_sink=captured.append,
        )
        wall_ms = round((perf_counter() - started) * 1000, 3)
        telemetry = captured[-1] if captured else {}
        print(json.dumps({
            "case": name,
            "wall_ms": wall_ms,
            "response_chars": len(response),
            "load_ms": telemetry.get("load_ms"),
            "prompt_eval_ms": telemetry.get("prompt_eval_ms"),
            "eval_ms": telemetry.get("eval_ms"),
            "prompt_tokens": telemetry.get("prompt_tokens"),
            "output_tokens": telemetry.get("output_tokens"),
            "tokens_per_second": telemetry.get("tokens_per_second"),
            "status": telemetry.get("status"),
            "model": telemetry.get("model"),
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
