"""Command line: python -m phishguard [file ...] [--offline] [--json]

With no file, paste the message and finish with Ctrl-D (Mac/Linux) or
Ctrl-Z then Enter (Windows).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import Result, check_message

COLOURS = {"safe": "\033[32m", "suspicious": "\033[33m", "phishing": "\033[31m"}
LABELS = {"safe": "SAFE", "suspicious": "SUSPICIOUS", "phishing": "PHISHING"}
RESET = "\033[0m"


def _print_result(name: str, result: Result, colour: bool) -> None:
    label = LABELS[result.verdict]
    if colour:
        label = f"{COLOURS[result.verdict]}{label}{RESET}"
    print(f"\n=== {name} ===")
    line = f"Verdict: {label}"
    if result.confidence is not None:
        line += f"  (confidence {result.confidence}%)"
    if result.attack_type and result.attack_type.lower() != "none":
        line += f"  - {result.attack_type}"
    print(line)
    print("Why:")
    for reason in result.reasons:
        print(f"  - {reason}")
    if result.used_ai and result.rule_findings:
        print(f"Local rule checks (score {result.rule_score}):")
        for finding in result.rule_findings:
            print(f"  - {finding}")
    print(f"What to do: {result.advice}")
    for note in result.notes:
        print(f"Note: {note}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Check an email or SMS for phishing. Gives safe, suspicious or phishing with reasons.",
    )
    parser.add_argument("files", nargs="*", help="Text files holding one message each. Leave out to paste a message.")
    parser.add_argument("--offline", action="store_true", help="Use only the local rules (no AWS, no cost).")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON for other programs.")
    parser.add_argument("--model", help="Bedrock model ID (default: anthropic.claude-opus-5-5, or $PHISHGUARD_MODEL).")
    args = parser.parse_args(argv)

    if args.files:
        messages = [(f, Path(f).read_text(encoding="utf-8", errors="replace")) for f in args.files]
    else:
        if sys.stdin.isatty():
            print("Paste the email or SMS, then press Ctrl-D (Mac/Linux) or Ctrl-Z then Enter (Windows):", file=sys.stderr)
        messages = [("pasted message", sys.stdin.read())]

    results = []
    for name, text in messages:
        try:
            result = check_message(text, use_ai=not args.offline, model=args.model)
        except ValueError as e:
            print(f"{name}: {e}", file=sys.stderr)
            return 2
        results.append((name, result))

    if args.json:
        payload = [{"file": name, **r.to_dict()} for name, r in results]
        print(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2))
    else:
        for name, result in results:
            _print_result(name, result, colour=sys.stdout.isatty())
    return 0


if __name__ == "__main__":
    sys.exit(main())
