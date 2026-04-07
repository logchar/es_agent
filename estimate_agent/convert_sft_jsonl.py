#!/usr/bin/env python3
"""Convert training JSONL files into SFT platform message-only JSONL format.

Input line example (current project):
  {
    "challenge_id": "...",
    "episode_id": "...",
    "step_id": 1,
    "messages": [...]
  }

Output line example (target SFT format):
  {
    "messages": [...]
  }
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert one or more JSONL files to SFT messages-only JSONL format."
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="Input file/dir/glob. Multiple values are supported.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSONL file path.",
    )
    parser.add_argument(
        "--pattern",
        default="*.jsonl",
        help="Glob pattern when an --input item is a directory (default: *.jsonl).",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Search directories recursively.",
    )
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        help="Deduplicate identical message lists.",
    )
    return parser.parse_args()


def resolve_input_files(inputs: Sequence[str], pattern: str, recursive: bool) -> List[Path]:
    files: List[Path] = []

    for item in inputs:
        p = Path(item)
        if p.is_file():
            files.append(p)
            continue

        if p.is_dir():
            if recursive:
                matched = sorted(p.rglob(pattern))
            else:
                matched = sorted(p.glob(pattern))
            files.extend([m for m in matched if m.is_file()])
            continue

        matched_glob = sorted(glob.glob(item, recursive=recursive))
        files.extend([Path(m) for m in matched_glob if Path(m).is_file()])

    unique_sorted = sorted({f.resolve() for f in files})
    return [Path(f) for f in unique_sorted]


def normalize_message(msg: Dict) -> Dict:
    role = str(msg.get("role", "")).strip()
    content = msg.get("content", "")

    normalized = {
        "role": role,
        "content": "" if content is None else str(content),
    }

    if "reasoning_content" in msg and msg["reasoning_content"] is not None:
        normalized["reasoning_content"] = str(msg["reasoning_content"])

    if "loss_weight" in msg:
        normalized["loss_weight"] = msg["loss_weight"]

    return normalized


def convert_line(obj: Dict) -> Dict:
    messages = obj.get("messages")
    if not isinstance(messages, list):
        raise ValueError("missing or invalid 'messages' list")

    normalized_messages = []
    for idx, msg in enumerate(messages, start=1):
        if not isinstance(msg, dict):
            raise ValueError(f"message #{idx} is not an object")
        normalized_messages.append(normalize_message(msg))

    return {"messages": normalized_messages}


def iter_jsonl_lines(file_path: Path) -> Iterable[Tuple[int, str]]:
    with file_path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            yield i, line.rstrip("\n")


def main() -> int:
    args = parse_args()
    input_files = resolve_input_files(args.input, args.pattern, args.recursive)

    if not input_files:
        print("[ERROR] No input files found.")
        return 1

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    converted = 0
    skipped = 0
    dedup_keys = set()

    with output_path.open("w", encoding="utf-8") as out_f:
        for in_file in input_files:
            in_file_resolved = in_file.resolve()
            if in_file_resolved == output_path:
                continue

            for line_no, raw_line in iter_jsonl_lines(in_file_resolved):
                if not raw_line.strip():
                    continue

                try:
                    obj = json.loads(raw_line)
                    converted_obj = convert_line(obj)

                    if args.deduplicate:
                        key = json.dumps(converted_obj["messages"], ensure_ascii=False, sort_keys=True)
                        if key in dedup_keys:
                            skipped += 1
                            continue
                        dedup_keys.add(key)

                    out_f.write(json.dumps(converted_obj, ensure_ascii=False) + "\n")
                    converted += 1
                except Exception as exc:
                    skipped += 1
                    print(f"[WARN] skip {in_file_resolved}:{line_no} -> {exc}")

    print(f"[DONE] files={len(input_files)}, converted={converted}, skipped={skipped}")
    print(f"[DONE] output={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
