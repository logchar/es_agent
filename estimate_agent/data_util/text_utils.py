from pathlib import Path
import re
from typing import List

from .constants import BENCHMARK_CANARY_RE, CANARY_BLOCK_RE


def redact_canary_text(text: str) -> str:
    """Remove benchmark canary text blocks from source text."""
    if not text:
        return text
    text = CANARY_BLOCK_RE.sub("", text)
    text = BENCHMARK_CANARY_RE.sub("", text)
    return text


def normalize_text(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def detect_challenge_id(path: Path, content: str) -> str:
    combined = f"{path}\n{content[:2000]}"
    m = re.search(r"XBEN-\d{3}-\d{2}", combined, re.IGNORECASE)
    if m:
        return m.group(0).upper()
    return path.stem.upper().replace(" ", "_")


def safe_read_text(path: Path, max_bytes: int = 200_000) -> str:
    try:
        raw = path.read_bytes()
    except Exception:
        return ""

    raw = raw[:max_bytes]
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def get_repo_root() -> Path:
    """Best-effort repository root (parent of estimate_agent package)."""
    return Path(__file__).resolve().parents[2]


def auto_discover_inputs(spec: str, repo_root: Path, challenge_id_hint: str = "") -> List[Path]:
    """
    Resolve user-provided --input values that are not direct file paths.
    """
    token = (spec or "").strip()
    if not token:
        return []

    is_pathish = ("/" in token) or ("\\" in token)

    cid_match = re.search(r"XBEN-\d{3}-\d{2}", token, re.IGNORECASE)
    detected_cid = cid_match.group(0).upper() if cid_match else ""
    hint = str(challenge_id_hint or "").strip().upper()
    challenge_id = detected_cid or hint
    suffix = Path(token).suffix.lower()
    basename = Path(token).name

    candidates: List[Path] = []

    if challenge_id:
        exploit_dir = repo_root / "vulnerables" / "exploit" / challenge_id
        if suffix in {".md", ".log"}:
            candidates.append(exploit_dir / f"{challenge_id}{suffix}")
            candidates.append(exploit_dir / basename)
        else:
            candidates.append(exploit_dir / f"{challenge_id}.md")
            candidates.append(exploit_dir / f"{challenge_id}.log")

        if exploit_dir.is_dir():
            candidates.extend(sorted(exploit_dir.glob("*.md")))
            candidates.extend(sorted(exploit_dir.glob("*.log")))

    if (not is_pathish) and suffix in {".md", ".log"}:
        if hint:
            search_roots = [repo_root / "vulnerables" / "exploit" / hint]
        else:
            search_roots = [
                repo_root / "vulnerables",
                repo_root / "penetration_agent",
                repo_root / "eval_results",
            ]
        for root in search_roots:
            if not root.is_dir():
                continue
            try:
                candidates.extend(list(root.rglob(basename)))
            except Exception:
                continue

    out: List[Path] = []
    seen = set()
    for p in candidates:
        if not isinstance(p, Path):
            continue
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".md", ".log"}:
            continue
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def expand_challenge_id_range(start_id: str, end_id: str) -> List[str]:
    start_match = re.fullmatch(r"(XBEN)-(\d{3})-(\d{2})", str(start_id).strip().upper())
    end_match = re.fullmatch(r"(XBEN)-(\d{3})-(\d{2})", str(end_id).strip().upper())
    if not start_match or not end_match:
        raise ValueError(f"invalid challenge id range: {start_id!r} -> {end_id!r}")
    if start_match.group(1) != end_match.group(1) or start_match.group(3) != end_match.group(3):
        raise ValueError(f"challenge id range must share the same prefix/suffix: {start_id!r} -> {end_id!r}")

    prefix = start_match.group(1)
    suffix = start_match.group(3)
    start_num = int(start_match.group(2))
    end_num = int(end_match.group(2))
    if end_num < start_num:
        start_num, end_num = end_num, start_num
    return [f"{prefix}-{num:03d}-{suffix}" for num in range(start_num, end_num + 1)]
