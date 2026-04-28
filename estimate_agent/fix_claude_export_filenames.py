#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
将 Claude 导出中「整段前缀重复一次」的过长文件名，规范为与 evaluator 期望一致的形式。

典型坏名（同一段 P 出现两次）:
  {P}_{P}_claude-session.jsonl
  {P}_{P}_conversation-export.txt

规范为:
  {P}_claude-session.jsonl
  {P}_conversation-export.txt

这能避免:
  - estimate_agent 里对 stem 的裁剪得到错误的 base，找不到 companion 文件
  - 人眼与脚本难以匹配

默认仅打印计划 (dry-run)，传 --apply 才执行重命名。

用法:
    # 预览
    python -m estimate_agent.fix_claude_export_filenames -d estimate_agent/gpt5.4-xben
    # 执行
    python -m estimate_agent.fix_claude_export_filenames -d estimate_agent/gpt5.4-xben --apply
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# 可扩展：其它后缀若也出现 P_P_ 模式可在此添加
DUP_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^(.+)_\1(_claude-session\.jsonl)$"), "claude session jsonl"),
    (re.compile(r"^(.+)_\1(_conversation-export\.txt)$"), "conversation export"),
]


def canonical_name(filename: str) -> str | None:
    """
    若整文件名匹配「重复前缀 P」，返回规范文件名；否则返回 None。
    """
    for pat, _label in DUP_PATTERNS:
        m = pat.match(filename)
        if m:
            return f"{m.group(1)}{m.group(2)}"
    return None


def plan_renames_in_dir(
    target_dir: Path, *, include_subdirs: bool
) -> list[tuple[Path, Path]]:
    out: list[tuple[Path, Path]] = []
    if not target_dir.is_dir():
        return out
    it = target_dir.rglob("*") if include_subdirs else target_dir.iterdir()
    for f in it:
        if not f.is_file() or f.name.startswith("."):
            continue
        newn = canonical_name(f.name)
        if newn is None or newn == f.name:
            continue
        out.append((f, f.parent / newn))
    return out


def _validate(pairs: list[tuple[Path, Path]]) -> list[str]:
    problems: list[str] = []
    by_dst: dict[Path, Path] = {}
    for src, dst in pairs:
        if dst in by_dst and by_dst[dst] != src:
            problems.append(f"多源指向同一目标: {by_dst[dst]} 与 {src} -> {dst}")
        by_dst[dst] = src
    for src, dst in pairs:
        if dst.exists() and dst.resolve() != src.resolve():
            problems.append(f"已存在(非本文件): {dst}（来自 {src}）")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(
        description="去重「{P}_{P}_」形式的 Claude 导出超长文件名"
    )
    ap.add_argument(
        "-d",
        "--dir",
        type=Path,
        default=Path(__file__).resolve().parent / "gpt5.4-xben",
        help="要扫描的目录（仅直接子文件；见 --recurse 扫子树）",
    )
    ap.add_argument(
        "--recurse",
        action="store_true",
        help="也处理子目录中的文件",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="真的重命名；否则只列出计划",
    )
    args = ap.parse_args()
    target = args.dir.resolve()
    plan = plan_renames_in_dir(target, include_subdirs=bool(args.recurse))
    bad = _validate(plan)
    if bad:
        for b in bad:
            print("ERROR: " + b, file=sys.stderr)
        if plan:
            print("放弃执行（有冲突时请先手工处理或清理目标文件）", file=sys.stderr)
        return 2
    if not plan:
        print(
            f"无需重命名：在 {target} 未发现「整段前缀重复 (P_P_)」的导出文件名。"
        )
        return 0
    for src, dst in sorted(plan, key=lambda x: str(x[0])):
        if args.apply:
            src.rename(dst)
            act = "OK"
        else:
            act = "dry-run"
        print(f"[{act}]\n  从: {src.name}\n  到: {dst.name}\n", flush=True)
    if not args.apply:
        print("以上为预览。确认无误后加 --apply 执行重命名。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
