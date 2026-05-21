#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
可视化 `eval_reports/*/MULTI-FALG*.txt` 这类多 flag 评估报告。

脚本会递归扫描 `eval_reports` 下各模型子目录中的 `MULTI-FALG*.txt`，
按模型聚合后输出：
  - 各模型综合分（含单文件散点、均值和标准差）
  - 定量 / 定性 / 综合分的对比图
  - 渗透侧与 Judge 侧请求数、耗时对比图
  - `summary.csv` 汇总表

用法:
  python eval_reports/visualize_multi_flag.py
  python eval_reports/visualize_multi_flag.py -d eval_reports --out multi-figure/multi_flag
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

REPORT_STEM_RE = re.compile(r"^MULTI-FALG_(?P<model>.+)$")
FLOAT = r"([\d.]+)"
INT = r"(\d+)"


@dataclass
class MultiFlagReport:
    source_path: Path
    model: str
    file_id: str

    agent_tokens: int | None = None
    agent_time_sec: float | None = None
    agent_requests: int | None = None
    agent_avg_response_sec: float | None = None

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
    qual_creative: float | None = None
    qual_drift: float | None = None

    step_window_overall: float | None = None
    step_window_scores: list[float] = field(default_factory=list)
    qual_total: float | None = None
    final_score: float | None = None
    grade: str | None = None
    parse_warnings: list[str] = field(default_factory=list)

    def warn(self, msg: str) -> None:
        self.parse_warnings.append(msg)


def _parse_int(text: str, pattern: str, data: MultiFlagReport, attr: str) -> None:
    match = re.search(pattern, text, re.MULTILINE)
    if match:
        setattr(data, attr, int(match.group(1)))


def _parse_float(text: str, pattern: str, data: MultiFlagReport, attr: str) -> None:
    match = re.search(pattern, text, re.MULTILINE)
    if match:
        setattr(data, attr, float(match.group(1)))


def parse_multi_flag_report(path: Path, text: str) -> MultiFlagReport:
    stem_match = REPORT_STEM_RE.match(path.stem)
    if not stem_match:
        raise ValueError(f"文件名不符合 MULTI-FALG_模型名 格式: {path.name}")

    model = path.parent.name
    file_id = path.stem[len("MULTI-FALG_") :]
    report = MultiFlagReport(source_path=path, model=model, file_id=file_id)

    _parse_int(text, rf"总Token使用量:\s*{INT}", report, "agent_tokens")
    _parse_float(text, rf"总用时:\s*{FLOAT}\s*秒", report, "agent_time_sec")
    _parse_int(text, rf"总请求次数:\s*{INT}", report, "agent_requests")
    _parse_float(text, rf"平均响应时间:\s*{FLOAT}\s*秒", report, "agent_avg_response_sec")

    _parse_int(text, rf"评估Token使用量:\s*{INT}", report, "judge_tokens")
    _parse_float(text, rf"评估总用时\(累计\):\s*{FLOAT}\s*秒", report, "judge_time_sec")
    _parse_int(text, rf"评估请求次数:\s*{INT}", report, "judge_requests")
    _parse_float(text, rf"评估平均响应时间:\s*{FLOAT}\s*秒", report, "judge_avg_response_sec")

    _parse_float(text, rf"定量得分:\s*{FLOAT}/10\.0", report, "score_quant")
    _parse_float(text, rf"Token 使用得分:\s*{FLOAT}/10\.0", report, "sub_token")
    _parse_float(text, rf"总耗时得分:\s*{FLOAT}/10\.0", report, "sub_time")
    _parse_float(text, rf"请求数量得分:\s*{FLOAT}/10\.0", report, "sub_requests")
    _parse_float(text, rf"平均响应时间得分:\s*{FLOAT}/10\.0", report, "sub_avg_rt")

    plan_match = re.search(
        r"方案规划质量:\s*" + FLOAT + r"/10\.0\s*\(confidence:\s*" + FLOAT + r"\)",
        text,
    )
    if plan_match:
        report.qual_plan = float(plan_match.group(1))

    creative_match = re.search(
        r"创造性:\s*" + FLOAT + r"/10\.0\s*\(confidence:\s*" + FLOAT + r"\)",
        text,
    )
    if creative_match:
        report.qual_creative = float(creative_match.group(1))

    drift_match = re.search(
        r"决策偏移度:\s*" + FLOAT + r"/10\.0\s*\(confidence:\s*" + FLOAT + r"\)",
        text,
    )
    if drift_match:
        report.qual_drift = float(drift_match.group(1))

    window_match = re.search(r"\[5-step\].*?overall_score=" + FLOAT, text, re.DOTALL)
    if window_match:
        report.step_window_overall = float(window_match.group(1))

    for window_score in re.finditer(r"Window \d+:\s*steps\s*\d+-\d+;\s*score=" + FLOAT, text):
        report.step_window_scores.append(float(window_score.group(1)))

    _parse_float(text, rf"定性得分:\s*{FLOAT}/10\.0", report, "qual_total")
    _parse_float(text, rf"综合得分:\s*{FLOAT}/10\.0", report, "final_score")

    grade_match = re.search(r"^等级:\s*(.+)\s*$", text, re.MULTILINE)
    if grade_match:
        report.grade = grade_match.group(1).strip()

    if report.final_score is None and report.score_quant is None and report.qual_total is None:
        report.warn("未解析到核心分数，请检查报告格式是否变更。")

    return report


def _load_cjk_font(plt) -> bool:
    from matplotlib import font_manager as fm

    candidates = [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    ]
    for candidate in candidates:
        if not Path(candidate).is_file():
            continue
        try:
            fm.fontManager.addfont(candidate)
            family = fm.FontProperties(fname=candidate).get_name()
            current = list(plt.rcParams["font.sans-serif"])
            if family not in current:
                plt.rcParams["font.sans-serif"] = [family, *current]
            return True
        except (OSError, ValueError, RuntimeError):
            continue
    return False


_HAS_CJK_FONT = True


def _setup_matplotlib() -> None:
    global _HAS_CJK_FONT
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _HAS_CJK_FONT = _load_cjk_font(plt)
    if not _HAS_CJK_FONT:
        plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["figure.dpi"] = 120
    plt.rcParams["savefig.dpi"] = 160
    plt.rcParams["figure.autolayout"] = True


def _z(zh: str, en: str) -> str:
    return zh if _HAS_CJK_FONT else en


def _safe_save(fig: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, bbox_inches="tight")
    import matplotlib.pyplot as plt

    plt.close(fig)


def _report_sort_key(report: MultiFlagReport) -> tuple[str, str]:
    return (report.model.lower(), report.file_id.lower())


def scan_multi_flag_reports(data_dir: Path) -> list[MultiFlagReport]:
    reports: list[MultiFlagReport] = []
    for path in sorted(data_dir.rglob("MULTI-FALG*.txt"), key=lambda p: p.as_posix().lower()):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"跳过 {path}: {exc}", file=sys.stderr)
            continue
        try:
            report = parse_multi_flag_report(path, text)
        except ValueError as exc:
            print(f"跳过 {path.name}: {exc}", file=sys.stderr)
            continue
        if report.parse_warnings:
            for warning in report.parse_warnings:
                print(f"[!] {path.name}: {warning}", file=sys.stderr)
        reports.append(report)
    return reports


def group_by_model(reports: list[MultiFlagReport]) -> dict[str, list[MultiFlagReport]]:
    grouped: dict[str, list[MultiFlagReport]] = defaultdict(list)
    for report in reports:
        grouped[report.model].append(report)
    for items in grouped.values():
        items.sort(key=_report_sort_key)
    return dict(sorted(grouped.items(), key=lambda item: item[0].lower()))


def _values(reports: list[MultiFlagReport], attr: str) -> list[float]:
    values: list[float] = []
    for report in reports:
        value = getattr(report, attr)
        if value is not None and math.isfinite(value):
            values.append(float(value))
    return values


def _mean_or_nan(values: list[float]) -> float:
    return mean(values) if values else float("nan")


def _stdev_or_zero(values: list[float]) -> float:
    return pstdev(values) if len(values) > 1 else 0.0


def build_summary_rows(grouped: dict[str, list[MultiFlagReport]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for model, items in grouped.items():
        finals = _values(items, "final_score")
        quants = _values(items, "score_quant")
        quals = _values(items, "qual_total")
        agent_requests = _values(items, "agent_requests")
        judge_requests = _values(items, "judge_requests")
        agent_time_sec = _values(items, "agent_time_sec")
        judge_time_sec = _values(items, "judge_time_sec")
        rows.append(
            {
                "model": model,
                "file_count": len(items),
                "final_mean": _mean_or_nan(finals),
                "final_std": _stdev_or_zero(finals),
                "quant_mean": _mean_or_nan(quants),
                "qual_mean": _mean_or_nan(quals),
                "agent_requests_mean": _mean_or_nan(agent_requests),
                "judge_requests_mean": _mean_or_nan(judge_requests),
                "agent_time_min_mean": (_mean_or_nan(agent_time_sec) / 60.0) if agent_time_sec else float("nan"),
                "judge_time_min_mean": (_mean_or_nan(judge_time_sec) / 60.0) if judge_time_sec else float("nan"),
                "step_window_overall_mean": _mean_or_nan(_values(items, "step_window_overall")),
                "plan_mean": _mean_or_nan(_values(items, "qual_plan")),
                "creative_mean": _mean_or_nan(_values(items, "qual_creative")),
                "drift_mean": _mean_or_nan(_values(items, "qual_drift")),
            }
        )
    return rows


def write_summary_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)


def fig_final_score_by_model(grouped: dict[str, list[MultiFlagReport]]) -> Any:
    import matplotlib.pyplot as plt
    import numpy as np

    rows = []
    for model, items in grouped.items():
        finals = _values(items, "final_score")
        rows.append((model, finals))
    rows.sort(key=lambda item: _mean_or_nan(item[1]), reverse=True)

    labels = [f"{model} (n={len(finals)})" for model, finals in rows]
    means = [_mean_or_nan(finals) for _, finals in rows]
    stds = [_stdev_or_zero(finals) for _, finals in rows]
    y = np.arange(len(rows))

    fig, ax = plt.subplots(figsize=(10.5, max(4.5, len(rows) * 0.55)))
    ax.barh(y, means, xerr=stds, color="#2E75B6", alpha=0.85, height=0.62, capsize=3)
    ax.set_yticks(y, labels, fontsize=8)
    ax.set_xlim(0, 10.5)
    ax.set_xlabel(_z("综合得分 (0–10)", "Final score (0–10)"))
    ax.set_title(_z("MULTI-FALG 各模型综合得分", "MULTI-FALG final score by model"))
    ax.grid(True, axis="x", alpha=0.25)
    for yi, mean_value, std_value in zip(y, means, stds):
        if math.isfinite(mean_value):
            ax.text(mean_value + std_value + 0.1, yi, f"{mean_value:.2f}", va="center", fontsize=8)

    for yi, (_, finals) in enumerate(rows):
        if not finals:
            continue
        offsets = np.linspace(-0.18, 0.18, num=len(finals)) if len(finals) > 1 else [0.0]
        ax.scatter(finals, np.full(len(finals), yi) + offsets, s=18, color="#4F81BD", alpha=0.55, zorder=3)

    fig.tight_layout()
    return fig


def fig_metric_grouped(grouped: dict[str, list[MultiFlagReport]]) -> Any:
    import matplotlib.pyplot as plt
    import numpy as np

    models = list(grouped.keys())
    x = np.arange(len(models), dtype=float)
    width = 0.25

    quant = [_mean_or_nan(_values(grouped[m], "score_quant")) for m in models]
    qual = [_mean_or_nan(_values(grouped[m], "qual_total")) for m in models]
    final = [_mean_or_nan(_values(grouped[m], "final_score")) for m in models]

    fig, ax = plt.subplots(figsize=(max(10, len(models) * 1.3), 5.5))
    ax.bar(x - width, quant, width, label=_z("定量均值", "Quant mean"), color="#5B9BD5")
    ax.bar(x, qual, width, label=_z("定性均值", "Qual mean"), color="#ED7D31")
    ax.bar(x + width, final, width, label=_z("综合均值", "Final mean"), color="#70AD47")
    ax.set_xticks(x, models, rotation=18, ha="right", fontsize=8)
    ax.set_ylabel(_z("得分 (0–10)", "Score (0–10)"))
    ax.set_ylim(0, 10.5)
    ax.set_title(_z("MULTI-FALG 定量 / 定性 / 综合平均分", "MULTI-FALG quant / qual / final means"))
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    return fig


def fig_resource_usage(grouped: dict[str, list[MultiFlagReport]]) -> Any:
    import matplotlib.pyplot as plt
    import numpy as np

    models = list(grouped.keys())
    y = np.arange(len(models), dtype=float)
    height = 0.32

    agent_req = [_mean_or_nan(_values(grouped[m], "agent_requests")) for m in models]
    judge_req = [_mean_or_nan(_values(grouped[m], "judge_requests")) for m in models]
    agent_min = [(_mean_or_nan(_values(grouped[m], "agent_time_sec")) / 60.0) for m in models]
    judge_min = [(_mean_or_nan(_values(grouped[m], "judge_time_sec")) / 60.0) for m in models]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, max(4.8, len(models) * 0.55)), sharey=True)

    ax1.barh(y - height / 2, agent_req, height, label=_z("渗透模型请求数", "Agent requests"), color="#4F81BD")
    ax1.barh(y + height / 2, judge_req, height, label=_z("Judge 请求数", "Judge requests"), color="#C0504D")
    ax1.set_yticks(y, models, fontsize=8)
    ax1.set_xlabel(_z("请求次数", "Requests"))
    ax1.set_title(_z("请求次数对比", "Request count"))
    ax1.grid(True, axis="x", alpha=0.25)
    ax1.legend(fontsize=8)

    ax2.barh(y - height / 2, agent_min, height, label=_z("渗透模型耗时", "Agent time"), color="#9BBB59")
    ax2.barh(y + height / 2, judge_min, height, label=_z("Judge 耗时", "Judge time"), color="#8064A2")
    ax2.set_xlabel(_z("分钟", "Minutes"))
    ax2.set_title(_z("耗时对比", "Time comparison"))
    ax2.grid(True, axis="x", alpha=0.25)
    ax2.legend(fontsize=8)

    fig.suptitle(_z("MULTI-FALG 资源消耗概览", "MULTI-FALG resource usage overview"), fontsize=13, fontweight="bold")
    fig.tight_layout()
    return fig


def fig_all_window_scores(grouped: dict[str, list[MultiFlagReport]]) -> Any:
    import matplotlib.pyplot as plt

    reports: list[MultiFlagReport] = []
    for model_reports in grouped.values():
        for report in model_reports:
            if report.step_window_scores:
                reports.append(report)

    if not reports:
        fig, ax = plt.subplots(figsize=(9.5, 5.0))
        ax.text(0.5, 0.5, _z("无窗口评分数据", "No window score data"), ha="center", va="center")
        ax.set_title(_z("所有模型窗口评分", "All models window scores"))
        return fig

    reports.sort(key=_report_sort_key)
    max_windows = max(len(report.step_window_scores) for report in reports)

    display_window_end = max_windows
    for window_idx in range(max_windows, 0, -1):
        scores_at_window = [
            report.step_window_scores[window_idx - 1]
            for report in reports
            if len(report.step_window_scores) >= window_idx
        ]
        if not scores_at_window:
            continue
        if len(set(scores_at_window)) > 1:
            display_window_end = window_idx
            break
    display_window_end = min(max_windows, max(8, display_window_end + 1))

    fig, ax = plt.subplots(figsize=(14.5, 7.6))
    cmap = plt.get_cmap("tab20" if len(reports) <= 20 else "nipy_spectral")
    for idx, report in enumerate(reports):
        x = list(range(1, len(report.step_window_scores) + 1))
        color = cmap(idx / max(1, len(reports) - 1)) if len(reports) > 1 else cmap(0.5)
        label = report.model if report.model == report.file_id else f"{report.model} ({report.file_id})"
        ax.plot(
            x,
            report.step_window_scores,
            marker="o",
            markersize=4.2,
            linewidth=2.0,
            alpha=0.96,
            color=color,
            label=label,
        )

    all_scores = [score for report in reports for score in report.step_window_scores]
    y_min = min(all_scores)
    y_max = max(all_scores)
    ax.set_xlim(0.5, max_windows + 0.5)
    lower = max(0.0, y_min - 0.8)
    upper = min(10.0, max(y_max + 0.5, lower + 2.5))
    ax.set_ylim(lower, upper)
    ax.set_xlim(0.5, display_window_end + 0.5)
    ax.set_xlabel(_z("窗口序号", "Window #"), fontsize=14)
    ax.set_ylabel(_z("分数", "Score"), fontsize=14)
    ax.set_title(_z("所有模型窗口评分（同图）", "All model window scores (combined)"), fontsize=15, pad=12)
    ax.grid(True, axis="y", alpha=0.22, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=11)
    ncol = 2 if len(reports) <= 10 else 3 if len(reports) <= 24 else 4
    ax.legend(
        loc="lower left",
        bbox_to_anchor=(0.015, 0.02),
        ncol=ncol,
        fontsize=14,
        frameon=True,
        framealpha=0.92,
        borderaxespad=0.0,
        handletextpad=0.7,
        labelspacing=0.5,
        columnspacing=1.2,
    )
    fig.tight_layout()
    return fig


def run(data_dir: Path, out_subdir: Path) -> list[Path]:
    _setup_matplotlib()
    import matplotlib.pyplot as plt

    data_dir = data_dir.resolve()
    out_root = (data_dir / out_subdir).resolve()

    reports = scan_multi_flag_reports(data_dir)
    if not reports:
        print(
            f"未找到任何可解析的 MULTI-FALG 报告。请确认目录下存在 {data_dir}/<model_name>/MULTI-FALG*.txt",
            file=sys.stderr,
        )
        return []

    grouped = group_by_model(reports)
    rows = build_summary_rows(grouped)
    out_root.mkdir(parents=True, exist_ok=True)

    csv_path = out_root / "summary.csv"
    write_summary_csv(rows, csv_path)

    written: list[Path] = []
    print(f"共加载 {len(reports)} 条 MULTI-FALG 报告，覆盖 {len(grouped)} 个模型 → {out_root}/")
    print(f"已写: {csv_path}")

    fig0 = fig_all_window_scores(grouped)
    p0 = out_root / "00_all_window_scores.png"
    _safe_save(fig0, p0)
    written.append(p0)
    print(f"已写: {p0}")

    fig1 = fig_final_score_by_model(grouped)
    p1 = out_root / "01_final_score_by_model.png"
    _safe_save(fig1, p1)
    written.append(p1)
    print(f"已写: {p1}")

    fig2 = fig_metric_grouped(grouped)
    p2 = out_root / "02_quant_qual_final_by_model.png"
    _safe_save(fig2, p2)
    written.append(p2)
    print(f"已写: {p2}")

    fig3 = fig_resource_usage(grouped)
    p3 = out_root / "03_resource_usage_by_model.png"
    _safe_save(fig3, p3)
    written.append(p3)
    print(f"已写: {p3}")

    plt.close("all")
    return written


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="可视化 eval_reports 下的 MULTI-FALG 报告")
    parser.add_argument(
        "-d",
        "--data-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="报告根目录，默认脚本所在目录 eval_reports",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("figures/multi_flag"),
        help="输出到 data-dir 下的相对路径，默认 figures/multi_flag",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run(args.data_dir, args.out)


if __name__ == "__main__":
    main()
