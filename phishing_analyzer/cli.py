"""Command-line interface."""
import argparse
import glob
import os
import sys

from . import __version__
from .analyzer import analyze_file
from .reporting import to_html, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Static phishing analysis of .eml files (headers, URLs, content, attachments).",
    )
    p.add_argument("paths", nargs="+", help=".eml files or directories containing them")
    p.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    p.add_argument("-o", "--output", help="Write report to this file (single input) or directory (multiple inputs)")
    p.add_argument("--vt", action="store_true", help="Query VirusTotal for hashes/URLs (needs VT_API_KEY)")
    p.add_argument("--fail-score", type=int, default=None,
                   help="Exit with code 2 if any email scores at or above this value (useful in CI/pipelines)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _collect(paths):
    files = []
    for path in paths:
        if os.path.isdir(path):
            files.extend(sorted(glob.glob(os.path.join(path, "*.eml"))))
        else:
            files.append(path)
    return files


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    files = _collect(args.paths)
    if not files:
        print("No .eml files found.", file=sys.stderr)
        return 1

    render = {"text": to_text, "json": to_json, "html": to_html}[args.format]
    ext = {"text": "txt", "json": "json", "html": "html"}[args.format]
    worst = 0

    for path in files:
        try:
            result = analyze_file(path, use_virustotal=args.vt)
        except (OSError, ValueError) as exc:
            print(f"Error analyzing {path}: {exc}", file=sys.stderr)
            continue
        worst = max(worst, result.score)
        report = render(result)

        if args.output:
            if len(files) == 1 and not os.path.isdir(args.output):
                out_path = args.output
            else:
                os.makedirs(args.output, exist_ok=True)
                out_path = os.path.join(args.output, os.path.basename(path) + f".{ext}")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"[{result.score:3}/100] {result.verdict:28} {path} -> {out_path}")
        else:
            print(report)

    if args.fail_score is not None and worst >= args.fail_score:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
