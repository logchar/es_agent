#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在「用户给定的根目录」下，只从各**模型子目录**中读取 `*.txt`（如 `deepseek_deepseek-v4-flash/*.txt`），
解析并出图；图输出到同一根目录下的 `charts/{model_name}/`（如 `charts/deepseek_deepseek-v4-flash/per_target/`、
`summary_*.png`）。

用法:
  python visualize_reports.py
  python visualize_reports.py --data-dir /path/to/eval_reports
  python visualize_reports.py -d . --charts charts
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# -----------------------------------------------------------------------------
# 解析
# -----------------------------------------------------------------------------

# 文件名: XBEN-123-24_z-ai_glm-5.txt → 靶场, 模型
STEM_RE = re.compile(r"^(?P<target>XBEN-\d+-\d+)_(?P<model>.+)$")
# 靶场序号 n：XBEN-n-24
TARGET_NUM_PAT = re.compile(r"^XBEN-(\d+)-\d+$")


def _report_order_key(d: "ReportData") -> tuple:
    m = TARGET_NUM_PAT.match(d.target)
    if m:
        return (int(m.group(1)), d.model)
    return (10**9, d.model)

FLOAT = r"([\d.]+)"
INT = r"(\d+)"


@dataclass
class ReportData:
    target: str
    model: str
    source_path: Path

    # 渗透侧
    agent_tokens: int | None = None
    agent_time_sec: float | None = None
    agent_requests: int | None = None
    agent_avg_response_sec: float | None = None

    # Judge
    judge_tokens: int | None = None
    judge_time_sec: float | None = None
    judge_requests: int | None = None
    judge_avg_response_sec: float | None = None

    score_quant: float | None = None
    sub_token: float | None = None
    sub_time: float | None = None
    sub_requests: float | None = None
    sub_avg_rt: float | None = None

    qual_plan: float | None = None
    qual_plan_conf: float | None = None
    qual_creative: float | None = None
    qual_creative_conf: float | None = None
    qual_drift: float | None = None
    qual_drift_conf: float | None = None

    step_window_overall: float | None = None
    step_window_scores: list[float] = field(default_factory=list)

    qual_total: float | None = None
    final_score: float | None = None
    grade: str | None = None
    parse_warnings: list[str] = field(default_factory=list)

    def warn(self, msg: str) -> None:
        self.parse_warnings.append(msg)


def _parse_int(text: str, pattern: str, data: ReportData, attr: str) -> None:
    m = re.search(pattern, text, re.MULTILINE)
    if m:
        setattr(data, attr, int(m.group(1)))


def _parse_float(text: str, pattern: str, data: ReportData, attr: str) -> None:
    m = re.search(pattern, text, re.MULTILINE)
    if m:
        setattr(data, attr, float(m.group(1)))


def parse_report_text(path: Path, text: str) -> ReportData:
    stem = path.stem
    m = STEM_RE.match(stem)
    if not m:
        raise ValueError(f"文件名不符合 靶场名_模型名 格式: {path.name}")
    d = ReportData(
        target=m.group("target"),
        model=m.group("model"),
        source_path=path,
    )

    _parse_int(text, rf"总Token使用量:\s*{INT}", d, "agent_tokens")
    _parse_float(text, rf"总用时:\s*{FLOAT}\s*秒", d, "agent_time_sec")
    _parse_int(text, rf"总请求次数:\s*{INT}", d, "agent_requests")
    _parse_float(text, rf"平均响应时间:\s*{FLOAT}\s*秒", d, "agent_avg_response_sec")

    _parse_int(text, rf"评估Token使用量:\s*{INT}", d, "judge_tokens")
    _parse_float(text, rf"评估总用时\(累计\):\s*{FLOAT}\s*秒", d, "judge_time_sec")
    _parse_int(text, rf"评估请求次数:\s*{INT}", d, "judge_requests")
    _parse_float(text, rf"评估平均响应时间:\s*{FLOAT}\s*秒", d, "judge_avg_response_sec")

    _parse_float(text, rf"定量得分:\s*{FLOAT}/10\.0", d, "score_quant")
    _parse_float(text, rf"Token 使用得分:\s*{FLOAT}/10\.0", d, "sub_token")
    _parse_float(text, rf"总耗时得分:\s*{FLOAT}/10\.0", d, "sub_time")
    _parse_float(text, rf"请求数量得分:\s*{FLOAT}/10\.0", d, "sub_requests")
    _parse_float(text, rf"平均响应时间得分:\s*{FLOAT}/10\.0", d, "sub_avg_rt")

    mp = re.search(
        r"方案规划质量:\s*" + FLOAT + r"/10\.0\s*\(confidence:\s*" + FLOAT + r"\)", text
    )
    if mp:
        d.qual_plan, d.qual_plan_conf = float(mp.group(1)), float(mp.group(2))
    mc = re.search(
        r"创造性:\s*" + FLOAT + r"/10\.0\s*\(confidence:\s*" + FLOAT + r"\)", text
    )
    if mc:
        d.qual_creative, d.qual_creative_conf = float(mc.group(1)), float(mc.group(2))
    md = re.search(
        r"决策偏移度:\s*" + FLOAT + r"/10\.0\s*\(confidence:\s*" + FLOAT + r"\)", text
    )
    if md:
        d.qual_drift, d.qual_drift_conf = float(md.group(1)), float(md.group(2))

    mo = re.search(
        r"\[5-step\].*?overall_score=" + FLOAT, text, re.DOTALL
    )
    if mo:
        d.step_window_overall = float(mo.group(1))

    for mw in re.finditer(
        r"Window \d+:\s*steps\s*\d+-\d+;\s*score=" + FLOAT, text
    ):
        d.step_window_scores.append(float(mw.group(1)))

    _parse_float(text, rf"定性得分:\s*{FLOAT}/10\.0", d, "qual_total")
    _parse_float(text, rf"综合得分:\s*{FLOAT}/10\.0", d, "final_score")
    mg = re.search(r"^等级:\s*(.+)\s*$", text, re.MULTILINE)
    if mg:
        d.grade = mg.group(1).strip()

    if d.final_score is None and d.score_quant is None and d.qual_total is None:
        d.warn("未解析到核心分数，请检查报告格式是否变更。")

    return d


# -----------------------------------------------------------------------------
# Matplotlib 设置
# -----------------------------------------------------------------------------

# 有有效中文字体时为 True，否则图中标题/轴使用英文
_CHART_ZH: bool = True


def _load_cjk_font(plt) -> bool:
    """在常见 Linux 路径注册 Noto/WenQuanYi 等，避免中文缺字。"""
    import os

    from matplotlib import font_manager as fm

    paths = [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    ]
    for p in paths:
        if not os.path.isfile(p):
            continue
        try:
            fm.fontManager.addfont(p)
            fam = fm.FontProperties(fname=p).get_name()
            cur = list(plt.rcParams["font.sans-serif"])
            if fam not in cur:
                plt.rcParams["font.sans-serif"] = [fam, *cur]
            return True
        except (OSError, ValueError, RuntimeError):
            continue
    return False


def _setup_matplotlib() -> None:
    global _CHART_ZH
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if _load_cjk_font(plt):
        _CHART_ZH = True
    else:
        _CHART_ZH = False
        plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]

    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["figure.dpi"] = 120
    plt.rcParams["savefig.dpi"] = 150
    plt.rcParams["figure.autolayout"] = True


def _z(zh: str, en: str) -> str:
    return zh if _CHART_ZH else en


# -----------------------------------------------------------------------------
# 出图
# -----------------------------------------------------------------------------


def _safe_save(fig: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, bbox_inches="tight")
    import matplotlib.pyplot as plt

    plt.close(fig)


def figure_per_target_windows_only(d: ReportData) -> "Any":
    """单靶场：仅 5-step window 分数折线（单张图）。"""
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 4.5))
    title = f"{d.target}  /  {d.model}"
    fig.suptitle(title, fontsize=13, fontweight="bold", y=1.02)

    if d.step_window_scores:
        w = list(range(1, len(d.step_window_scores) + 1))
        ax.plot(
            w, d.step_window_scores, marker="o", markersize=3, linewidth=1, color="#2E75B6"
        )
        ax.set_xlabel(_z("Window 序号", "Window #"))
        ax.set_ylabel("Score")
        y_hi = max(d.step_window_scores)
        ax.set_ylim(-0.5, max(7.0, y_hi * 1.1))
        if _CHART_ZH:
            tl = f"5-step 窗口分（共 {len(d.step_window_scores)} 窗）"
        else:
            tl = f"5-step window scores (n={len(d.step_window_scores)})"
        if d.step_window_overall is not None:
            tl += f"  |  overall={d.step_window_overall:.3f}"
        ax.set_title(tl, fontsize=11)
        ax.grid(True, alpha=0.3)
    else:
        ax.text(
            0.5,
            0.5,
            _z("无步骤窗口数据", "No step-window data"),
            ha="center",
            va="center",
            transform=ax.transAxes,
        )
        ax.set_title(_z("步骤窗口分", "Step windows"))

    return fig


def figure_all_window_scores(reports: list[ReportData]) -> "Any":
    """同一张图内叠加各靶场（各文件）的 window 分数曲线；横轴为 Window 序号。"""
    import matplotlib.pyplot as plt

    with_data = [r for r in reports if r.step_window_scores]
    if not with_data:
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.text(0.5, 0.5, _z("无步骤窗口数据", "No step-window data"), ha="center", va="center")
        ax.set_title(
            _z("全部靶场 5-step window 分数", "All targets: 5-step window scores")
        )
        return fig

    n = max(len(d.step_window_scores) for d in with_data)
    fig, ax = plt.subplots(figsize=(12, 6.5))
    rep = sorted(with_data, key=_report_order_key)
    cmap = plt.get_cmap("tab20" if len(rep) <= 20 else "nipy_spectral")
    for i, d in enumerate(rep):
        scores = d.step_window_scores
        w = list(range(1, len(scores) + 1))
        c = cmap(i / max(1, len(rep) - 1)) if len(rep) > 1 else cmap(0.5)
        label = f"{d.target} ({d.model})"
        ax.plot(
            w,
            scores,
            marker="o",
            markersize=1.5,
            linewidth=0.9,
            color=c,
            label=label,
            alpha=0.9,
        )

    ax.set_xlabel(_z("Window 序号", "Window #"))
    ax.set_ylabel("Score")
    y_hi = max(max(d.step_window_scores) for d in with_data)
    ax.set_ylim(-0.5, max(7.0, y_hi * 1.1))
    ax.set_xlim(0.5, n + 0.5)
    ax.grid(True, alpha=0.25)
    ax.set_title(
        _z(
            "全部靶场 5-step window 分数（按靶场序号图例）",
            "All targets: 5-step window scores (legend in target id order)",
        )
    )
    ncols = 2 if len(rep) <= 16 else 3
    ax.legend(
        bbox_to_anchor=(0.5, -0.18),
        loc="upper center",
        ncol=ncols,
        fontsize=7,
        frameon=True,
    )
    fig.tight_layout()
    return fig


def figure_summary_bars(reports: list[ReportData]) -> "Any":
    """多靶场：综合得分的横向条形图；按靶场序号升序，不按分数重排。"""
    import matplotlib.pyplot as plt
    import numpy as np

    if not reports:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, _z("无数据", "No data"), ha="center")
        return fig

    rep = sorted(reports, key=_report_order_key)
    labels = [f"{r.target} ({r.model})" for r in rep]
    scores = [r.final_score if r.final_score is not None else 0.0 for r in rep]
    y = np.arange(len(rep))

    fig, ax = plt.subplots(figsize=(9, max(4, len(rep) * 0.35)))
    ax.barh(y, scores, color="#5B9BD5", height=0.65)
    ax.set_yticks(y, labels, fontsize=8)
    ax.set_xlabel(_z("综合得分 (0–10)", "Final score (0–10)"))
    ax.set_xlim(0, 10.5)
    ax.set_title(
        _z("各靶场综合得分（按靶场序号升序）", "Final score by target id (ascending)")
    )
    ax.grid(True, axis="x", alpha=0.3)
    for yi, s in zip(y, scores):
        ax.text(s + 0.1, yi, f"{s:.2f}", va="center", fontsize=8)
    return fig


def _iter_model_subdirs(data_dir: Path) -> list[tuple[Path, list[Path]]]:
    """
    在 data_dir 下只扫描「直接子目录」中的 `*.txt`（如 `data_dir/deepseek_.../XBEN-*.txt`），
    不读取 data_dir 根目录上的 txt。

    始终跳过名为 `charts` 的目录，避免把输出目录当成模型名。
    """
    groups: list[tuple[Path, list[Path]]] = []
    skip_sub = {"charts", "__pycache__", ".git", ".cursor"}
    try:
        subs = sorted(data_dir.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return groups

    for sub in subs:
        if not sub.is_dir() or sub.name.startswith("."):
            continue
        if sub.name in skip_sub:
            continue
        txts = sorted(p for p in sub.glob("*.txt") if p.is_file())
        if txts:
            groups.append((sub, txts))
    return groups


def _process_group(group_dir: Path, txt_files: list[Path], out_root: Path) -> list[Path]:
    """在 group_dir 下将图表写入 out_root（含 per_target、summary_*.png）。"""
    all_data: list[ReportData] = []
    written: list[Path] = []

    for f in txt_files:
        if f.name.startswith("."):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"跳过 {f.name}: {e}")
            continue
        try:
            d = parse_report_text(f, text)
        except ValueError as e:
            print(f"跳过 {f.name}: {e}")
            continue
        if d.parse_warnings:
            for w in d.parse_warnings:
                print(f"[!] {f.name}: {w}")
        all_data.append(d)
        fig = figure_per_target_windows_only(d)
        p = out_root / "per_target" / f"{f.stem}.png"
        _safe_save(fig, p)
        written.append(p)
        print(f"已写: {p}")

    if len(all_data) >= 1:
        f_allw = figure_all_window_scores(all_data)
        p_allw = out_root / "summary_all_window_scores.png"
        _safe_save(f_allw, p_allw)
        written.append(p_allw)
        print(f"已写: {p_allw}")

        f3 = figure_summary_bars(all_data)
        p3 = out_root / "summary_final_scores.png"
        _safe_save(f3, p3)
        written.append(p3)
        print(f"已写: {p3}")

    return written


def run(data_dir: Path, charts_stem: str) -> list[Path]:
    """
    从 `data_dir/<model_name>/*.txt` 读入，图写入 `data_dir/{charts_stem}/<model_name>/`。
    """
    _setup_matplotlib()
    import matplotlib.pyplot as plt

    data_dir = data_dir.resolve()
    chart_parent = (data_dir / Path(charts_stem)).resolve()

    groups = _iter_model_subdirs(data_dir)
    if not groups:
        print(
            f"未在 {data_dir} 的直接子目录中找到 .txt 报告；"
            f"请使用布局：{data_dir}/<model_name>/*.txt（如 deepseek_.../XBEN-..._....txt）"
        )
        return []

    all_written: list[Path] = []
    for model_subdir, files in groups:
        model_name = model_subdir.name
        out_root = chart_parent / model_name
        print(f"\n--- 模型: {model_name}  ({len(files)} 个 txt) → {out_root} ---")
        all_written.extend(_process_group(model_subdir, files, out_root))
    return all_written


def main() -> None:
    p = argparse.ArgumentParser(description="评估报告 txt 批量可视化")
    script_dir = Path(__file__).resolve().parent
    p.add_argument(
        "-d",
        "--data-dir",
        type=Path,
        default=script_dir,
        help="根目录：其**直接子目录**名为 model_name 且内含 `*.txt` 报告。默认：本脚本所在目录",
    )
    p.add_argument(
        "--charts",
        type=str,
        default="charts",
        help="在根目录下存放图表的父目录名，最终路径为 {data_dir}/{charts}/{model_name}/，默认 charts",
    )
    args = p.parse_args()
    run(args.data_dir, args.charts)
    import matplotlib.pyplot as plt

    plt.close("all")


if __name__ == "__main__":
    main()
