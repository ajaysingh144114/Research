"""Command line: ``phishguard check message.eml`` or ``phishguard text "Your parcel ..."``."""

from __future__ import annotations

import argparse
import json
import sys

from .verdict import Analyzer


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phishguard", description="Check emails and messages for phishing links and forged senders")
    p.add_argument("--offline", action="store_true", help="skip threat feeds and domain-age lookups")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    p.add_argument("--allow", action="append", default=[], metavar="DOMAIN", help="your own domains, never flagged as lookalikes")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="analyse a raw .eml file (use - for stdin)")
    c.add_argument("file")
    t = sub.add_parser("text", help="analyse a text message or pasted body")
    t.add_argument("message", nargs="+")
    args = p.parse_args(argv)

    analyzer = Analyzer(feeds=[] if args.offline else None, check_age=not args.offline, allow_domains=args.allow)
    if args.cmd == "check":
        raw = sys.stdin.buffer.read() if args.file == "-" else open(args.file, "rb").read()
        v = analyzer.analyse_email(raw)
    else:
        v = analyzer.analyse_text(" ".join(args.message))

    if args.json:
        print(json.dumps(v.to_dict(), indent=2, default=str))
    else:
        print(f"{v.level.upper()}  score {v.score}/100")
        for r in v.reasons:
            print(f"  - {r}")
        if not v.reasons:
            print("  - no suspicious links or sender problems found")
    return 0 if v.level == "safe" else 1


if __name__ == "__main__":
    sys.exit(main())
