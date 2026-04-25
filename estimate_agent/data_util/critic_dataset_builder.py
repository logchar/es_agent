from __future__ import annotations

import json
import random
from typing import Any, Dict, List

from .critic_synthesis import (
    build_reference_solution,
    build_run_from_step,
    merge_arena_infos,
    render_critic_report,
    sample_negative_kinds,
    score_for,
    summarize_reference,
    truncate,
)
from .schemas import ExtractedStep


def build_critic_rows(
    *,
    challenge_id: str,
    reference_steps: List[ExtractedStep],
    env_ctx: Dict[str, Any],
    source_file: str,
    created_at: str,
    num_negatives_per_step: int,
    max_ref_chars: int,
    max_run_chars: int,
    rng: random.Random,
    system_prompt: str,
) -> List[Dict[str, Any]]:
    if not reference_steps:
        return []

    reference_solution = build_reference_solution(reference_steps)
    ref_text = summarize_reference(reference_steps, max_chars=max_ref_chars)
    merged_arena = merge_arena_infos(env_ctx, reference_steps)

    rubric = {
        "score_range": "0-10",
        "guide": [
            "9-10: key path complete with evidence loop",
            "8-9: mostly correct, missing 1-2 key verification points",
            "5-8: partially correct but major evidence gaps / skipped checks",
            "0-5: off track / contradicts reference / a little correct",
        ],
    }

    rows: List[Dict[str, Any]] = []
    total = len(reference_steps)

    for step in reference_steps:
        step_key = (
            reference_solution["steps"][step.index - 1]["step_key"]
            if step.index - 1 < len(reference_solution["steps"])
            else f"step_{step.index:02d}"
        )

        for run_kind in ["on_track"] + sample_negative_kinds(num_negatives_per_step, rng=rng):
            run = build_run_from_step(step, run_kind=run_kind, rng=rng)
            run["text_summary"] = truncate(str(run.get("text_summary") or ""), max_chars=max_run_chars)

            score, conf, track = score_for(run_kind, step_index=step.index, total_steps=total, rng=rng)
            report = render_critic_report(
                score=score,
                confidence=conf,
                track=track,
                matched_step_key=step_key,
                run=run,
                reference_solution=reference_solution,
            )

            input_payload = {
                "challenge_id": challenge_id,
                "episode_id": f"{challenge_id}_ep01",
                "time": created_at,
                "challenge_digest": {
                    "environment": env_ctx,
                    "arena": merged_arena,
                    "source_files": [source_file],
                    "notes": "This digest may include solution hints for training the critic.",
                },
                "reference_solution": {
                    **reference_solution,
                    "text_summary": ref_text,
                },
                "run": run,
                "rubric": rubric,
                "task": "Score the run correctness against the reference solution and explain why.",
                "output_requirements": {
                    "must_include": [
                        "[SCORE]",
                        "[CONFIDENCE]",
                        "[TRACK]",
                        "[MATCHED_STEP]",
                        "Summary",
                        "Evidence",
                        "Deviations",
                    ],
                    "language": "zh",
                },
            }

            rows.append(
                {
                    "challenge_id": challenge_id,
                    "episode_id": f"{challenge_id}_ep01",
                    "sample_kind": run_kind,
                    "step_id": step.index,
                    "created_at": created_at,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": json.dumps(input_payload, ensure_ascii=False)},
                        {"role": "assistant", "content": report},
                    ],
                }
            )

    return rows
