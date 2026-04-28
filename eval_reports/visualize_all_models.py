#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
聚合 `eval_reports` 下**所有**模型子目录的 `*.txt` 报告，生成交叉模型对比图。

会跳过（不作为模型名扫描）：`__pycache__`、`chart`、`charts`、`figures`、以 `.` 开头目录等。

输出目录：默认 `{data_dir}/figures/all_models/`
  - `01_heatmap_final_model_x_target.png` — 模型×靶场 综合分热力图
  - `02_bar_mean_final_by_model.png` — 各模型综合分均值与标准差
  - `03_boxplot_final_by_model.png` — 各模型综合分箱线图
  - `04_grouped_subscores.png` — 各模型 定量/定性/综合 均值（分组柱）

与 `visualize_reports.py` 使用相同的报告解析与字体逻辑。

用法:
  python eval_reports/visualize_all_models.py
  python eval_reports/visualize_all_models.py -d /path/to/eval_reports
  python eval_reports/visualize_all_models.py -d . --out figures/aggregate
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# 与 visualize_reports 同目录，保证以脚本/包方式运行均可
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from visualize_reports import (  # noqa: E402
    ReportData,
    TARGET_NUM_PAT,
    _setup_matplotlib,
    _z,
    parse_report_text,
)


# ---------------------------------------------------------------------------
# 发现报告文件（在 visualize_reports 的跳过列表上增加 chart、figures）
# ---------------------------------------------------------------------------

SKIP_DIR_NAMES = frozenset(
    {
        "charts",
        "chart",
        "figures",
        "__pycache__",
        ".git",
        ".cursor",
    }
)


def _target_sort_key(target: str) -> tuple:
    m = TARGET_NUM_PAT.match(target)
    if m:
        return (0, int(m.group(1)), target)
    return (1, 0, target)


def iter_model_txt_groups(data_dir: Path) -> list[tuple[Path, list[Path]]]:
    """`data_dir/<model_name>/*.txt`，同 visualize_reports 布局。"""
    groups: list[tuple[Path, list[Path]]] = []
    try:
        subs = sorted(data_dir.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return groups
    for sub in subs:
        if not sub.is_dir() or sub.name.startswith("."):
            continue
        if sub.name in SKIP_DIR_NAMES:
            continue
        txts = sorted(p for p in sub.glob("*.txt") if p.is_file())
        if txts:
            groups.append((sub, txts))
    return groups


def load_all_reports(data_dir: Path) -> list[ReportData]:
    all_rows: list[ReportData] = []
    for model_dir, files in iter_model_txt_groups(data_dir):
        for f in files:
            if f.name.startswith("."):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                print(f"跳过 {f}: {e}", file=sys.stderr)
                continue
            try:
                d = parse_report_text(f, text)
            except ValueError as e:
                print(f"跳过 {f.name}: {e}", file=sys.stderr)
                continue
            if d.parse_warnings:
                for w in d.parse_warnings:
                    print(f"[!] {f.name}: {w}", file=sys.stderr)
            if d.model != model_dir.name:
                print(
                    f"[!] 汇总以目录名为模型 id：目录={model_dir.name}，"
                    f"文件名解析为 {d.model}  ← {f.name}",
                    file=sys.stderr,
                )
            d.model = model_dir.name
            all_rows.append(d)
    return all_rows


def _safe_save(fig: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, bbox_inches="tight")
    import matplotlib.pyplot as plt

    plt.close(fig)


# ---------------------------------------------------------------------------
# 出图
# ---------------------------------------------------------------------------


def _matrix_final_scores(reports: list[ReportData]) -> tuple[list[str], list[str], "Any"]:
    import numpy as np

    by_pair: dict[tuple[str, str], float] = {}
    for r in reports:
        if r.final_score is None:
            continue
        key = (r.model, r.target)
        if key in by_pair and by_pair[key] != r.final_score:
            print(f"[!] 重复 (model, target) 将覆盖: {key}", file=sys.stderr)
        by_pair[key] = r.final_score

    models = sorted({m for m, _ in by_pair}, key=str.lower)
    targets = sorted({t for _, t in by_pair}, key=_target_sort_key)

    n_m, n_t = len(models), len(targets)
    mat = np.full((n_m, n_t), np.nan, dtype=np.float64)
    mi = {m: i for i, m in enumerate(models)}
    tj = {t: j for j, t in enumerate(targets)}
    for (m, t), s in by_pair.items():
        mat[mi[m], tj[t]] = s
    return models, targets, mat


def fig_heatmap(
    models: list[str], targets: list[str], mat: "Any", title_zh: str
) -> "Any":
    import matplotlib.pyplot as plt
    import numpy as np

    fig, ax = plt.subplots(figsize=(max(10, len(targets) * 0.45), max(4.5, len(models) * 0.4)))
    im = ax.imshow(mat, aspect="auto", cmap="RdYlGn", vmin=0.0, vmax=10.0, interpolation="nearest")
    cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cbar.set_label(_z("综合得分 (0–10)", "Final score (0–10)"))
    ax.set_xticks(np.arange(len(targets)))
    ax.set_yticks(np.arange(len(models)))
    ax.set_xticklabels(targets, rotation=60, ha="right", fontsize=7)
    ax.set_yticklabels(models, fontsize=8)
    ax.set_xlabel(_z("靶场", "Target / range"))
    ax.set_ylabel(_z("模型", "Model"))
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            v = mat[i, j]
            if np.isfinite(v):
                tcol = "white" if v < 4.5 or v > 7.5 else "black"
                ax.text(
                    j,
                    i,
                    f"{v:.1f}",
                    ha="center",
                    va="center",
                    color=tcol,
                    fontsize=6,
                )
    fig.suptitle(title_zh, fontsize=12, fontweight="bold", y=1.01)
    return fig


def fig_bar_mean_by_model(reports: list[ReportData]) -> "Any":
    import matplotlib.pyplot as plt
    import numpy as np

    m_scores: dict[str, list[float]] = defaultdict(list)
    for r in reports:
        if r.final_score is not None:
            m_scores[r.model].append(r.final_score)
    if not m_scores:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, _z("无综合分数据", "No final_score"), ha="center", va="center")
        return fig
    order = sorted(m_scores.keys(), key=str.lower)
    means = [float(np.mean(m_scores[m])) for m in order]
    stds = [float(np.std(m_scores[m], ddof=0)) for m in order]
    n = [len(m_scores[m]) for m in order]
    y = np.arange(len(order))
    fig, ax = plt.subplots(figsize=(9, max(4, len(order) * 0.4)))
    ax.barh(y, means, xerr=stds, color="#2E75B6", capsize=2, height=0.6)
    ax.set_yticks(y, order, fontsize=8)
    ax.set_xlabel(_z("综合分均值 (± 标准差)", "Mean final score (± stdev)"))
    ax.set_xlim(0, 10.5)
    for yi, m, s, c in zip(y, means, stds, n):
        ax.text(m + s + 0.1, yi, f"{m:.2f} (n={c})", va="center", fontsize=7)
    ax.set_title(_z("各模型综合分均值", "Mean final score by model"))
    ax.grid(True, axis="x", alpha=0.3)
    return fig


def fig_boxplot_final(reports: list[ReportData]) -> "Any":
    import matplotlib.pyplot as plt
    import numpy as np

    m_scores: dict[str, list[float]] = defaultdict(list)
    for r in reports:
        if r.final_score is not None:
            m_scores[r.model].append(r.final_score)
    if not m_scores:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, _z("无数据", "No data"), ha="center")
        return fig
    order = sorted(m_scores.keys(), key=str.lower)
    data = [m_scores[m] for m in order]
    fig, ax = plt.subplots(figsize=(max(7, len(order) * 1.1), 5.5))
    ax.boxplot(data, labels=order, showmeans=True)
    ax.set_ylabel(_z("综合得分 (0–10)", "Final score (0–10)"))
    ax.set_title(_z("各模型综合分分布（箱线）", "Final score distribution by model"))
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=8)
    ax.grid(True, axis="y", alpha=0.3)
    return fig


def fig_grouped_subscores(reports: list[ReportData]) -> "Any":
    import matplotlib.pyplot as plt
    import numpy as np

    agg: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: {"quant": [], "qual": [], "final": []}
    )
    for r in reports:
        a = agg[r.model]
        if r.score_quant is not None:
            a["quant"].append(r.score_quant)
        if r.qual_total is not None:
            a["qual"].append(r.qual_total)
        if r.final_score is not None:
            a["final"].append(r.final_score)
    if not agg:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, _z("无数据", "No data"), ha="center")
        return fig
    order = sorted(agg.keys(), key=str.lower)
    w = 0.22
    x = np.arange(len(order), dtype=np.float64)
    fig, ax = plt.subplots(figsize=(max(8, len(order) * 1.2), 5.0))

    def mean_list(xs: list[float]) -> float:
        return float(np.mean(xs)) if xs else float("nan")

    q1 = [mean_list(agg[m]["quant"]) for m in order]
    q2 = [mean_list(agg[m]["qual"]) for m in order]
    q3 = [mean_list(agg[m]["final"]) for m in order]

    ax.bar(x - w, q1, w, label=_z("定量均值", "Quant mean"), color="#5B9BD5")
    ax.bar(x, q2, w, label=_z("定性均值", "Qual mean"), color="#ED7D31")
    ax.bar(x + w, q3, w, label=_z("综合均值", "Final mean"), color="#70AD47")
    ax.set_xticks(x, order, rotation=25, ha="right", fontsize=8)
    ax.set_ylabel(_z("得分 (0–10)", "Score (0–10)"))
    ax.set_ylim(0, 10.5)
    ax.set_title(
        _z("各模型 定量/定性/综合 平均分（在已有样本上求均值，缺失子项不计入）", "Per-model mean of quant/qual/final (skip missing)"),
    )
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)
    return fig


def run(data_dir: Path, out_subdir: Path) -> list[Path]:
    _setup_matplotlib()
    import matplotlib.pyplot as plt
    data_dir = data_dir.resolve()
    out_root = (data_dir / out_subdir).resolve()

    reports = load_all_reports(data_dir)
    if not reports:
        print(
            f"未找到任何可解析的 txt 报告。请确认目录为：{data_dir}/<model_name>/*.txt",
            file=sys.stderr,
        )
        return []

    written: list[Path] = []
    print(f"共加载 {len(reports)} 条报告 → {out_root}/")

    models, targets, mat = _matrix_final_scores(reports)
    if mat.size:
        htitle = _z("所有模型：综合得分 热力图（行=模型，列=靶场）", "All models: final score heatmap")
        fig_h = fig_heatmap(models, targets, mat, htitle)
        p = out_root / "01_heatmap_final_model_x_target.png"
        _safe_save(fig_h, p)
        written.append(p)
        print(f"已写: {p}")

    fig_m = fig_bar_mean_by_model(reports)
    p2 = out_root / "02_bar_mean_final_by_model.png"
    _safe_save(fig_m, p2)
    written.append(p2)
    print(f"已写: {p2}")

    fig_b = fig_boxplot_final(reports)
    p3 = out_root / "03_boxplot_final_by_model.png"
    _safe_save(fig_b, p3)
    written.append(p3)
    print(f"已写: {p3}")

    fig_g = fig_grouped_subscores(reports)
    p4 = out_root / "04_grouped_subscores.png"
    _safe_save(fig_g, p4)
    written.append(p4)
    print(f"已写: {p4}")

    plt.close("all")
    return written


def main() -> None:
    ap = argparse.ArgumentParser(
        description="跨模型汇总：读取 eval_reports 下各模型子目录的 txt 并出对比图"
    )
    ap.add_argument(
        "-d",
        "--data-dir",
        type=Path,
        default=_SCRIPT_DIR,
        help="与 visualize_reports 相同：根目录，其下直接子目录为模型名。默认本脚本所在目录 (eval_reports)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("figures/all_models"),
        help="输出在 data-dir 下的相对路径。默认 figures/all_models",
    )
    args = ap.parse_args()
    run(args.data_dir, args.out)


if __name__ == "__main__":
    main()
