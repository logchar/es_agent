from __future__ import annotations

import glob
from pathlib import Path
from typing import List, Sequence

from .text_utils import auto_discover_inputs, get_repo_root


def resolve_input_files(inputs: Sequence[str], recursive: bool, challenge_id_hint: str) -> List[Path]:
    repo_root = get_repo_root()
    files: List[Path] = []

    for item in inputs:
        p = Path(item)
        if p.is_file():
            files.append(p)
            continue

        if p.is_dir():
            matches = list(p.rglob("*") if recursive else p.glob("*"))
            files.extend([m for m in matches if m.is_file()])
            continue

        matched = sorted(glob.glob(item, recursive=recursive))
        if matched:
            files.extend([Path(m) for m in matched if Path(m).is_file()])
            continue

        discovered = auto_discover_inputs(item, repo_root=repo_root, challenge_id_hint=challenge_id_hint)
        files.extend(discovered)

    uniq: List[Path] = []
    seen = set()
    for f in files:
        if f.suffix.lower() not in {".md", ".log"}:
            continue
        key = str(f.resolve())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return sorted(uniq)
