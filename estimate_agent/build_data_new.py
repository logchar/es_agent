#!/usr/bin/env python3
# coding: utf-8
"""Build critic-style training data (评分器/审阅者) from challenge writeups.

This script is intentionally separate from build_training_data.py.

It generates JSONL where each line contains `messages` for SFT:
- system: critic role
- user: JSON payload (reference solution + challenge digest + a run trace)
- assistant: natural-language scoring report (NOT JSON-only)

The primary goal is to teach the model challenge-specific solutions and
how to grade a run against a reference trajectory.

Typical usage:
  python -m estimate_agent.build_data_new \
    --challenge-id XBEN-015-24 \
    --output-dir estimate_agent/generated_critic_data \
    --env-root vulnerables/benchmark_envs \
    --num-negatives-per-step 2

  # Build a range
  python -m estimate_agent.build_data_new \
    --challenge-range XBEN-014-24 XBEN-060-24 \
    --output-dir estimate_agent/generated_critic_data
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from estimate_agent.data_util.constants import DEFAULT_ENV_ROOT
from estimate_agent.data_util.critic_dataset_builder import build_critic_rows
from estimate_agent.data_util.critic_io import resolve_input_files
from estimate_agent.data_util.critic_step_extraction import (
    extract_steps_from_markdown,
    llm_extract_steps_async,
)
from estimate_agent.data_util.environment_utils import (
    load_environment_context,
    load_estimate_client_if_enabled,
)
from estimate_agent.data_util.schemas import ExtractedStep
from estimate_agent.data_util.text_utils import (
    expand_challenge_id_range,
    get_repo_root,
    normalize_text,
)

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


CRITIC_SYSTEM_PROMPT = (
    "You are a penetration-testing run critic. Compare the agent's run against the reference solution "
    "for this challenge. Provide a score and reasons. "
    "Do NOT provide exploit payloads or step-by-step attack instructions. Focus on evaluation."
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build critic-style JSONL training data")
    p.add_argument("--challenge-id", action="append", default=[], help="Challenge id, e.g. XBEN-015-24. Can be repeated.")
    p.add_argument("--challenge-range", nargs=2, metavar=("START", "END"), help="Challenge id range, e.g. XBEN-014-24 XBEN-060-24")
    p.add_argument("--input", nargs="+", default=[], help="Optional explicit input files/dirs/globs (md/log).")
    p.add_argument("--recursive", action="store_true", help="Search input directories recursively")
    p.add_argument("--env-root", default=str(DEFAULT_ENV_ROOT), help="Benchmark env root dir")
    p.add_argument("--output-dir", default="estimate_agent/generated_critic_data", help="Output dir for critic JSONL")
    p.add_argument("--min-steps", type=int, default=6, help="Minimum number of extracted steps to accept")
    p.add_argument("--enable-llm", action="store_true", default=False, help="Enable LLM extraction fallback")
    p.add_argument("--llm-model", default=os.getenv("ESTIMATE_MODEL_NAME", "").strip(), help="LLM model name for extraction")
    p.add_argument("--seed", type=int, default=1337, help="Random seed")
    p.add_argument("--num-negatives-per-step", type=int, default=2, help="How many negative variants to generate per step")
    p.add_argument("--max_ref_chars", type=int, default=6000, help="Max chars for reference_solution.text_summary")
    p.add_argument("--max_run_chars", type=int, default=4000, help="Max chars for run.text_summary")
    p.add_argument("--merge-by-challenge", action="store_true", help="Append to per-challenge output file")
    return p.parse_args()


def llm_extract_steps_sync(
    *,
    content: str,
    file_type: str,
    model: str,
    max_steps: int,
    client: Any,
) -> List[ExtractedStep]:
    if not client:
        return []
    try:
        return asyncio.run(
            llm_extract_steps_async(
                content=content,
                file_type=file_type,
                model=model,
                max_steps=max_steps,
                client=client,
            )
        )
    except RuntimeError:
        # If already inside an event loop, skip LLM fallback.
        return []

def extract_reference_steps(
    *,
    file_path: Path,
    env_ctx: Dict[str, Any],
    min_steps: int,
    enable_llm: bool,
    llm_model: str,
    client: Any,
) -> List[ExtractedStep]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    content = normalize_text(text)

    if file_path.suffix.lower() != ".md":
        # For now, treat only markdown writeups as reference.
        return []

    steps = extract_steps_from_markdown(content=content, min_steps=min_steps, env_ctx=env_ctx)
    if enable_llm and (len(steps) < min_steps):
        llm_steps = llm_extract_steps_sync(
            content=content,
            file_type="md",
            model=llm_model,
            max_steps=max(40, min_steps * 2),
            client=client,
        )
        if llm_steps:
            steps = llm_steps

    return steps


def discover_challenge_ids(exploit_root: Path) -> List[str]:
    if not exploit_root.is_dir():
        return []
    out: List[str] = []
    for p in sorted(exploit_root.iterdir()):
        if not p.is_dir():
            continue
        m = re.fullmatch(r"XBEN-\d{3}-\d{2}", p.name.upper())
        if m:
            out.append(p.name.upper())
    return out


def main() -> int:
    args = parse_args()

    if load_dotenv:
        load_dotenv()

    rng = random.Random(args.seed)

    env_root = Path(args.env_root)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    repo_root = get_repo_root()
    exploit_root = repo_root / "vulnerables" / "exploit"

    challenge_ids: List[str] = [c.strip().upper() for c in args.challenge_id if str(c).strip()]
    if args.challenge_range:
        challenge_ids.extend(expand_challenge_id_range(args.challenge_range[0], args.challenge_range[1]))

    if not challenge_ids:
        challenge_ids = discover_challenge_ids(exploit_root)

    client = load_estimate_client_if_enabled()
    created_at = datetime.now(timezone.utc).isoformat()

    total_rows = 0
    for challenge_id in challenge_ids:
        env_ctx = load_environment_context(challenge_id=challenge_id, env_root=env_root)

        # Collect input markdown writeups.
        if args.input:
            input_files = resolve_input_files(args.input, recursive=args.recursive, challenge_id_hint=challenge_id)
        else:
            exploit_dir = exploit_root / challenge_id
            input_files = sorted([p for p in exploit_dir.glob("*.md") if p.is_file()])

        if not input_files:
            print(f"[WARN] no inputs for {challenge_id}")
            continue

        challenge_rows: List[Dict[str, Any]] = []
        for fp in input_files:
            steps = extract_reference_steps(
                file_path=fp,
                env_ctx=env_ctx,
                min_steps=args.min_steps,
                enable_llm=True,
                llm_model=os.getenv("ESTIMATE_MODEL_NAME", "").strip(),
                client=client,
            )
            if not steps:
                continue

            challenge_rows.extend(
                build_critic_rows(
                    challenge_id=challenge_id,
                    reference_steps=steps,
                    env_ctx=env_ctx,
                    source_file=str(fp),
                    created_at=created_at,
                    num_negatives_per_step=args.num_negatives_per_step,
                    max_ref_chars=args.max_ref_chars,
                    max_run_chars=args.max_run_chars,
                    rng=rng,
                    system_prompt=CRITIC_SYSTEM_PROMPT,
                )
            )

        if not challenge_rows:
            print(f"[WARN] no rows produced for {challenge_id}")
            continue

        out_path = out_dir / f"{challenge_id}_critic_samples.jsonl"
        mode = "a" if args.merge_by_challenge and out_path.exists() else "w"
        with out_path.open(mode, encoding="utf-8") as f:
            for row in challenge_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

        total_rows += len(challenge_rows)
        print(f"[OK] challenge_id={challenge_id} rows={len(challenge_rows)} output={out_path}")

    print(f"[DONE] total_rows={total_rows} output_dir={out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
