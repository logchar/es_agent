from __future__ import annotations

import json
import random
import re
from typing import Any, Dict, List, Sequence, Tuple

from .action_utils import (
    bootstrap_arena_info_from_env,
    infer_action_type,
    infer_target,
    normalize_action_item,
    normalize_arena_info,
)
from .schemas import ExtractedStep


def truncate(text: str, max_chars: int) -> str:
    t = (text or "").strip()
    if max_chars <= 0:
        return ""
    if len(t) <= max_chars:
        return t
    return t[: max(0, max_chars - 15)].rstrip() + "... [truncated]"


def safe_slug(text: str, max_len: int = 40) -> str:
    s = re.sub(r"\s+", "_", (text or "").strip().lower())
    s = re.sub(r"[^a-z0-9_\-\u4e00-\u9fff]", "", s)
    s = s.strip("_-")
    if not s:
        return "step"
    return s[:max_len]


def summarize_reference(steps: Sequence[ExtractedStep], max_chars: int) -> str:
    parts: List[str] = []
    for s in steps:
        parts.append(f"{s.index}. {str(s.detail or '').strip()}")
    return truncate("\n".join(parts), max_chars=max_chars)


def build_reference_solution(steps: Sequence[ExtractedStep]) -> Dict[str, Any]:
    ref_steps: List[Dict[str, Any]] = []
    for s in steps:
        step_key = f"step_{s.index:02d}_{safe_slug(str(s.detail or ''), max_len=28)}"
        ref_steps.append(
            {
                "step_key": step_key,
                "title": s.title or f"step_{s.index}",
                "detail": s.detail,
                "expected_actions": [
                    {
                        "action_type": str(s.action_type or "").strip() or infer_action_type(s.detail),
                        "target": str(s.target or "").strip() or infer_target(s.detail),
                    }
                ],
            }
        )
    return {"version": "v1", "steps": ref_steps}


def merge_arena_infos(env_ctx: Dict[str, Any], steps: Sequence[ExtractedStep]) -> Dict[str, Any]:
    merged = bootstrap_arena_info_from_env(env_ctx)
    for s in steps:
        merged = _merge_arena_info_dicts(merged, normalize_arena_info(s.arena_info))
    return merged


def _merge_arena_info_dicts(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k in [
        "known_endpoints",
        "known_credentials",
        "known_ids",
        "known_parameters",
        "known_artifacts",
        "suspected_vulns",
    ]:
        vals: List[Any] = []
        for src in (a, b):
            v = src.get(k)
            if isinstance(v, list):
                vals.extend(v)
        dedup: List[Any] = []
        seen = set()
        for v in vals:
            key = json.dumps(v, ensure_ascii=False, sort_keys=True) if isinstance(v, (dict, list)) else str(v)
            if key in seen:
                continue
            seen.add(key)
            dedup.append(v)
        out[k] = dedup
    out["auth_state"] = b.get("auth_state") or a.get("auth_state") or "unknown"
    out["notes"] = (str(a.get("notes") or "").strip() + "\n" + str(b.get("notes") or "").strip()).strip()
    return out


def build_run_from_step(step: ExtractedStep, run_kind: str, rng: random.Random) -> Dict[str, Any]:
    executed: List[Dict[str, Any]] = []
    raw_executed = step.executed_key_actions if isinstance(step.executed_key_actions, list) else []
    for item in raw_executed:
        norm = normalize_action_item(item)
        if norm is not None:
            executed.append(norm)

    if not executed:
        executed.append(
            {
                "action_type": str(step.action_type or "").strip() or infer_action_type(step.detail),
                "target": str(step.target or "").strip() or infer_target(step.detail),
                "outcome": "partial",
                "evidence": step.detail,
            }
        )

    observed = normalize_arena_info(step.arena_info)
    text_bits = [
        f"当前步骤: {step.index} / {step.title}",
        f"描述: {step.detail}",
    ]
    if observed.get("notes"):
        text_bits.append(f"笔记: {observed['notes']}")

    if run_kind == "partial":
        if executed:
            victim = rng.choice(executed)
            victim["outcome"] = "partial"
            if victim.get("evidence"):
                victim["evidence"] = truncate(victim["evidence"], 80)
        if isinstance(observed.get("known_endpoints"), list) and len(observed["known_endpoints"]) > 2:
            observed["known_endpoints"] = observed["known_endpoints"][:2]
        text_bits.append("(提示) 轨迹整体方向正确，但证据/验证不充分。")

    if run_kind == "off_track":
        noise_actions = [
            {
                "action_type": "PROBE_ENDPOINT",
                "target": "/admin",
                "outcome": "fail",
                "evidence": "Tried /admin and got 404",
            },
            {
                "action_type": "ENUM_ID_RANGE",
                "target": "bruteforce ids",
                "outcome": "partial",
                "evidence": "Enumerated random IDs without rationale",
            },
            {
                "action_type": "PROBE_ENDPOINT",
                "target": "/debug",
                "outcome": "fail",
                "evidence": "Access denied",
            },
        ]
        executed = noise_actions + executed[: max(0, len(executed) - 1)]
        if isinstance(observed.get("suspected_vulns"), list):
            observed["suspected_vulns"] = list(
                {"SQLi", "RCE", "XSS"} | set(map(str, observed.get("suspected_vulns", [])))
            )
        text_bits.append("(警告) 轨迹包含与题解不一致的探索/假设。")

    return {
        "run_kind": run_kind,
        "current_step": {"index": step.index, "title": step.title, "claimed_outcome": step.outcome},
        "observed": observed,
        "actions": [{"seq": i + 1, **a} for i, a in enumerate(executed)],
        "text_summary": "\n".join(text_bits).strip(),
    }


def sample_negative_kinds(n: int, *, rng: random.Random) -> List[str]:
    if n <= 0:
        return []
    kinds = ["partial", "off_track"]
    return [rng.choice(kinds) for _ in range(n)]


def score_for(run_kind: str, step_index: int, total_steps: int, rng: random.Random) -> Tuple[float, float, str]:
    progress = 0.0 if total_steps <= 0 else max(0.0, min(1.0, step_index / float(total_steps)))

    if run_kind == "on_track":
        base = 6.8 + 3.2 * progress
        jitter = rng.uniform(-0.3, 0.3)
        score = max(0.0, min(10.0, base + jitter))
        conf = max(0.0, min(1.0, 0.7 + 0.2 * progress + rng.uniform(-0.08, 0.08)))
        track = "on_track"
    elif run_kind == "partial":
        base = 4.5 + 3.0 * progress
        jitter = rng.uniform(-0.5, 0.4)
        score = max(0.0, min(8.6, base + jitter))
        conf = max(0.0, min(1.0, 0.55 + 0.15 * progress + rng.uniform(-0.12, 0.08)))
        track = "partial"
    else:
        base = 1.0 + 1.8 * progress
        jitter = rng.uniform(-0.6, 0.6)
        score = max(0.0, min(3.5, base + jitter))
        conf = max(0.0, min(1.0, 0.5 + rng.uniform(-0.18, 0.18)))
        track = "off_track"

    return round(score, 2), round(conf, 2), track


def render_critic_report(
    *,
    score: float,
    confidence: float,
    track: str,
    matched_step_key: str,
    run: Dict[str, Any],
    reference_solution: Dict[str, Any],
) -> str:
    run_summary = str(run.get("text_summary") or "").strip()
    actions = run.get("actions") if isinstance(run.get("actions"), list) else []
    observed = run.get("observed") if isinstance(run.get("observed"), dict) else {}

    evidence_lines: List[str] = []
    if isinstance(observed.get("known_endpoints"), list) and observed["known_endpoints"]:
        evidence_lines.append(f"- 已识别端点: {', '.join(map(str, observed['known_endpoints'][:5]))}")
    if isinstance(observed.get("known_parameters"), list) and observed["known_parameters"]:
        evidence_lines.append(f"- 已识别参数: {', '.join(map(str, observed['known_parameters'][:5]))}")
    if actions:
        last = actions[-1]
        evidence_lines.append(
            f"- 最近动作: {last.get('action_type')} -> {last.get('target')} (outcome={last.get('outcome')})"
        )

    deviations: List[str] = []
    if track == "on_track":
        deviations.append("- (med) 仍建议补齐关键成功条件的证据闭环（例如明确的成功标识/flag 提取证据）。")
    elif track == "partial":
        deviations.append("- (high) 缺少关键验证/证据，当前结论可能基于假设而非响应事实。")
        deviations.append("- (med) 建议对照题解步骤补齐缺失的检查点，再继续推进。")
    else:
        deviations.append("- (high) 当前轨迹与参考题解不一致，可能在错误攻击面上消耗时间。")
        deviations.append("- (med) 需要回到题解的关键入口点/关键参数，重新建立证据链。")

    corrections: List[str] = []
    if track != "on_track":
        corrections.append("- 对照参考步骤，先完成最早缺失的关键检查点（例如登录/枚举关键对象/确认漏洞点）。")
        corrections.append("- 为每个关键假设补充 1 条可复现证据（响应特征/状态码/页面元素/日志关键行）。")

    ref_steps = reference_solution.get("steps") if isinstance(reference_solution.get("steps"), list) else []
    ref_titles: List[str] = []
    for i, st in enumerate(ref_steps[:8], start=1):
        title = st.get("title") if isinstance(st, dict) else ""
        if title:
            ref_titles.append(f"{i}. {title}")

    report = [
        f"[SCORE] {score}/10",
        f"[CONFIDENCE] {confidence}",
        f"[TRACK] {track}",
        f"[MATCHED_STEP] {matched_step_key}",
        "",
        "Summary:",
        f"- 总体评价：当前轨迹为 {track}，与参考步骤匹配程度取决于证据完整性与关键检查点覆盖。",
    ]

    if run_summary:
        report.extend(["", "Run snapshot:", *[f"- {line}" for line in run_summary.splitlines() if line.strip()]])

    if ref_titles:
        report.extend(["", "Reference (titles excerpt):", *[f"- {t}" for t in ref_titles]])

    report.extend(["", "Evidence:", *evidence_lines] if evidence_lines else ["", "Evidence:", "- (none)"])
    report.extend(["", "Deviations / Missing:", *deviations])

    if corrections:
        report.extend(["", "Minimal corrections (high-level):", *corrections])

    return "\n".join(report).strip() + "\n"
