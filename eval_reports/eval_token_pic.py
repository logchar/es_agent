#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
对比两个报告目录中的 token 使用量。

脚本会递归读取两个目录下的所有 `.txt` 报告，解析每个报告里的
"总Token使用量"，按文件名中的靶场编号对齐后画在同一张分组柱状图中。

用法:
  python eval_reports/eval_token_pic.py \
	--dir-a eval_reports/openai_gpt-5.4 \
	--dir-b eval_reports/anthropic_claude-opus-4.7 \
	--name-a GPT-5.4 \
	--name-b Claude Opus 4.7

  python eval_reports/eval_token_pic.py \
	-a eval_reports/openai_gpt-5.4 \
	-b eval_reports/openai_gpt-5.4-mini \
	-na "GPT-5.4" -nb "GPT-5.4 Mini"
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


STEM_RE = re.compile(r"^(?P<target>XBEN-\d+-\d+)_(?P<model>.+)$")
TOKEN_RE = re.compile(r"评估Token使用量:\s*(\d+)")
TARGET_NUM_RE = re.compile(r"^XBEN-(\d+)-\d+$")
_HAS_CJK_FONT = False


def _target_sort_key(stem: str) -> tuple[int, str]:
	match = TARGET_NUM_RE.match(stem)
	if match:
		return (int(match.group(1)), stem)
	return (10**9, stem)


def _collect_txt_files(directory: Path) -> list[Path]:
	return sorted(
		(path for path in directory.rglob("*.txt") if path.is_file()),
		key=lambda path: path.name.lower(),
	)


def _parse_tokens(path: Path) -> tuple[str, int] | None:
	match = STEM_RE.match(path.stem)
	if not match:
		return None
	text = path.read_text(encoding="utf-8", errors="replace")
	token_match = TOKEN_RE.search(text)
	if not token_match:
		return None
	return match.group("target"), int(token_match.group(1))


def load_directory_tokens(directory: Path) -> dict[str, int]:
	tokens: dict[str, int] = {}
	for path in _collect_txt_files(directory):
		parsed = _parse_tokens(path)
		if parsed is None:
			print(f"[!] 跳过无法解析的文件: {path}")
			continue
		target, token_count = parsed
		tokens[target] = token_count
	return tokens


def _make_output_path(output: Path | None, name_a: str, name_b: str) -> Path:
	if output is not None:
		return output
	safe_a = re.sub(r"[^\w.-]+", "_", name_a).strip("_") or "group_a"
	safe_b = re.sub(r"[^\w.-]+", "_", name_b).strip("_") or "group_b"
	return Path(__file__).with_name(f"token_compare_{safe_a}_vs_{safe_b}.png")


def _load_cjk_font() -> bool:
	from matplotlib import font_manager as fm

	paths = [
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/truetype/noto-cjk/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
		"/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
		"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
	]
	for path in paths:
		if not Path(path).is_file():
			continue
		try:
			fm.fontManager.addfont(path)
			family = fm.FontProperties(fname=path).get_name()
			current = list(plt.rcParams["font.sans-serif"])
			if family not in current:
				plt.rcParams["font.sans-serif"] = [family, *current]
			return True
		except (OSError, ValueError, RuntimeError):
			continue
	return False


def _setup_matplotlib() -> None:
	global _HAS_CJK_FONT
	_HAS_CJK_FONT = _load_cjk_font()
	if not _HAS_CJK_FONT:
		plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]
	plt.rcParams["axes.unicode_minus"] = False


def _z(chinese: str, english: str) -> str:
	return chinese if _HAS_CJK_FONT else english


def plot_token_comparison(
	data_a: dict[str, int],
	data_b: dict[str, int],
	name_a: str,
	name_b: str,
	output: Path,
) -> None:
	_setup_matplotlib()

	targets = sorted(set(data_a) | set(data_b), key=_target_sort_key)
	if not targets:
		raise ValueError("两个目录都没有可绘制的数据")

	values_a = [data_a.get(target, np.nan) for target in targets]
	values_b = [data_b.get(target, np.nan) for target in targets]

	x = np.arange(len(targets))
	width = 0.38

	fig, ax = plt.subplots(figsize=(max(12, len(targets) * 0.42), 6.5))
	bars_a = ax.bar(x - width / 2, values_a, width, label=name_a, color="#2E75B6")
	bars_b = ax.bar(x + width / 2, values_b, width, label=name_b, color="#C55A11")

	ax.set_title(_z("Token 使用量对比", "Token usage comparison"), fontsize=14, fontweight="bold")
	ax.set_xlabel(_z("靶场编号", "Target ID"))
	ax.set_ylabel(_z("Token 使用量", "Token usage"))
	ax.set_xticks(x)
	ax.set_xticklabels(targets, rotation=45, ha="right")
	ax.grid(True, axis="y", alpha=0.3)
	ax.legend()

	def _annotate(bars: Iterable[plt.Rectangle]) -> None:
		for bar in bars:
			height = bar.get_height()
			if not np.isfinite(height):
				continue
			ax.annotate(
				f"{int(height)}",
				(bar.get_x() + bar.get_width() / 2, height),
				xytext=(0, 3),
				textcoords="offset points",
				ha="center",
				va="bottom",
				fontsize=8,
			)

	_annotate(bars_a)
	_annotate(bars_b)

	fig.tight_layout()
	output.parent.mkdir(parents=True, exist_ok=True)
	fig.savefig(output, dpi=180, bbox_inches="tight")
	plt.close(fig)


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="对比两个目录下所有报告的 token 使用量")
	parser.add_argument("-a", "--dir-a", required=True, type=Path, help="第一个报告目录")
	parser.add_argument("-b", "--dir-b", required=True, type=Path, help="第二个报告目录")
	parser.add_argument("-na", "--name-a", required=True, help="图例中第一个对象的名称")
	parser.add_argument("-nb", "--name-b", required=True, help="图例中第二个对象的名称")
	parser.add_argument("-o", "--output", type=Path, help="输出图片路径")
	return parser


def main() -> None:
	parser = build_parser()
	args = parser.parse_args()

	dir_a = args.dir_a.expanduser().resolve()
	dir_b = args.dir_b.expanduser().resolve()
	if not dir_a.is_dir():
		raise FileNotFoundError(f"目录不存在: {dir_a}")
	if not dir_b.is_dir():
		raise FileNotFoundError(f"目录不存在: {dir_b}")

	data_a = load_directory_tokens(dir_a)
	data_b = load_directory_tokens(dir_b)

	output = _make_output_path(args.output, args.name_a, args.name_b).expanduser().resolve()
	plot_token_comparison(data_a, data_b, args.name_a, args.name_b, output)
	print(f"已保存对比图: {output}")


if __name__ == "__main__":
	main()
