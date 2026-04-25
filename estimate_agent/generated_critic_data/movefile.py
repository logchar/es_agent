"""Move unused critic sample files to backup.

Keeps only `{challenge_code}_critic_samples.jsonl` files whose `challenge_code`
exists as a subfolder under `vulnerables/benchmark_envs`.

All other `*_critic_samples.jsonl` files under this directory are moved to
`backup/`.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


CRITIC_SUFFIX = "_critic_samples.jsonl"


def _repo_root_from_this_file() -> Path:
	# .../es_agent/estimate_agent/generated_critic_data/movefile.py
	# parents[0]=generated_critic_data, [1]=estimate_agent, [2]=es_agent
	return Path(__file__).resolve().parents[2]


def _list_challenge_codes(benchmark_envs_dir: Path) -> set[str]:
	if not benchmark_envs_dir.exists():
		raise FileNotFoundError(f"benchmark_envs dir not found: {benchmark_envs_dir}")
	return {p.name for p in benchmark_envs_dir.iterdir() if p.is_dir()}


def _unique_target_path(target: Path) -> Path:
	if not target.exists():
		return target

	# Avoid clobbering: add numeric suffix before the file extension.
	# e.g. XBEN-002-24_critic_samples.jsonl -> ..._critic_samples.1.jsonl
	stem = target.stem
	suffix = target.suffix  # ".jsonl"
	parent = target.parent
	i = 1
	while True:
		candidate = parent / f"{stem}.{i}{suffix}"
		if not candidate.exists():
			return candidate
		i += 1


def move_unused_critic_samples(
	*,
	generated_dir: Path,
	benchmark_envs_dir: Path,
	backup_dir: Path,
	apply: bool,
	verbose: bool,
) -> int:
	challenge_codes = _list_challenge_codes(benchmark_envs_dir)

	if not generated_dir.exists():
		raise FileNotFoundError(f"generated_critic_data dir not found: {generated_dir}")

	candidates = sorted(generated_dir.glob(f"*{CRITIC_SUFFIX}"))
	if not candidates:
		print(f"No critic sample files found in {generated_dir}")
		return 0

	keep: list[Path] = []
	to_move: list[Path] = []

	for path in candidates:
		code = path.name[: -len(CRITIC_SUFFIX)]
		if code in challenge_codes:
			keep.append(path)
		else:
			to_move.append(path)

	if verbose:
		print(f"Challenge codes found: {len(challenge_codes)}")
		print(f"Critic sample files found: {len(candidates)}")
		print(f"Keeping: {len(keep)}")
		print(f"Moving: {len(to_move)}")

	if not to_move:
		print("Nothing to move.")
		return 0

	if apply:
		backup_dir.mkdir(parents=True, exist_ok=True)

	moved_count = 0
	for src in to_move:
		dst = _unique_target_path(backup_dir / src.name)
		if verbose or not apply:
			action = "MOVE" if apply else "DRY-RUN"
			print(f"{action}: {src} -> {dst}")
		if apply:
			shutil.move(str(src), str(dst))
			moved_count += 1

	print(f"Done. Moved {moved_count}/{len(to_move)} files to {backup_dir}.")
	return 0


def _build_arg_parser() -> argparse.ArgumentParser:
	repo_root = _repo_root_from_this_file()
	default_generated = repo_root / "estimate_agent" / "generated_critic_data"
	default_benchmark = repo_root / "vulnerables" / "benchmark_envs"
	default_backup = default_generated / "backup"

	parser = argparse.ArgumentParser(
		description=(
			"Keep only {challenge_code}_critic_samples.jsonl that correspond to "
			"subfolders under vulnerables/benchmark_envs; move others to backup."
		)
	)
	parser.add_argument(
		"--generated-dir",
		type=Path,
		default=default_generated,
		help=f"Directory containing critic sample files (default: {default_generated})",
	)
	parser.add_argument(
		"--benchmark-envs-dir",
		type=Path,
		default=default_benchmark,
		help=f"benchmark_envs directory (default: {default_benchmark})",
	)
	parser.add_argument(
		"--backup-dir",
		type=Path,
		default=default_backup,
		help=f"Backup directory (default: {default_backup})",
	)
	parser.add_argument(
		"--apply",
		action="store_true",
		help="Actually move files (default is dry-run)",
	)
	parser.add_argument(
		"--verbose",
		action="store_true",
		help="Print summary and every move operation",
	)
	return parser


def main(argv: list[str] | None = None) -> int:
	parser = _build_arg_parser()
	args = parser.parse_args(argv)
	return move_unused_critic_samples(
		generated_dir=args.generated_dir,
		benchmark_envs_dir=args.benchmark_envs_dir,
		backup_dir=args.backup_dir,
		apply=args.apply,
		verbose=args.verbose,
	)


if __name__ == "__main__":
	raise SystemExit(main())
