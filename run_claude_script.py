#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import shlex
import signal
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Optional


DEFAULT_TIMEOUT_SECONDS = 3 * 60


AUTO_REPLY_RULES: list[tuple[re.Pattern[str], str]] = [
    # yes/no style prompts
    (re.compile(r"(\[Y/n\]|\[y/N\]|\(y/n\)|y/n|yes/no)\s*$", re.IGNORECASE), "y\n"),
    (re.compile(r"\bcontinue\??\s*$", re.IGNORECASE), "y\n"),
    (re.compile(r"\bproceed\??\s*$", re.IGNORECASE), "y\n"),
    (re.compile(r"\bconfirm\??\s*$", re.IGNORECASE), "y\n"),
    # press enter prompts
    (re.compile(r"(press\s+enter|hit\s+enter)\s+to\s+(continue|proceed)\s*$", re.IGNORECASE), "\n"),
]


@dataclass(frozen=True)
class SessionResult:
    port: str
    exit_code: Optional[int]
    timed_out: bool
    elapsed_seconds: float


def _parse_ports(s: str) -> list[str]:
    s = s.strip()
    if not s:
        return []
    # allow comma/space separated
    parts = re.split(r"[,\s]+", s)
    return [p for p in (x.strip() for x in parts) if p]


def _kill_process_group(pgid: int, sig: int, grace_seconds: float) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return
    deadline = time.time() + grace_seconds
    while time.time() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.2)


def run_one_session(
    *,
    claude_cmd: list[str],
    prompt: str,
    timeout_seconds: int,
    auto_reply: bool,
    print_io: bool,
) -> tuple[Optional[int], bool, float]:
    """
    Run one Claude Code session in a PTY. Optionally auto-reply to prompts.
    Returns (exit_code, timed_out, elapsed_seconds).
    """
    import pty
    import select
    import subprocess
    import tty

    start = time.time()
    timed_out = False

    master_fd, slave_fd = pty.openpty()
    try:
        # Keep PTY in a reasonable mode
        tty.setraw(master_fd, when=tty.TCSAFLUSH)
    except Exception:
        pass

    # Many CLIs accept prompt as an argument; we pass it as the final arg.
    # If your local Claude Code expects stdin instead, you can change this to write prompt to PTY after spawn.
    argv = [*claude_cmd, prompt]

    proc = subprocess.Popen(
        argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=os.setsid,  # new process group for clean termination
        close_fds=True,
        text=False,
        env=os.environ.copy(),
    )
    pgid = os.getpgid(proc.pid)

    # Buffer to detect prompts across chunks
    tail = b""

    try:
        while True:
            now = time.time()
            if timeout_seconds > 0 and now - start >= timeout_seconds:
                timed_out = True
                break

            rlist, _, _ = select.select([master_fd], [], [], 0.2)
            if master_fd in rlist:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    chunk = b""

                if chunk:
                    if print_io:
                        try:
                            sys.stdout.buffer.write(chunk)
                            sys.stdout.buffer.flush()
                        except Exception:
                            pass

                    if auto_reply:
                        tail = (tail + chunk)[-4096:]
                        try:
                            tail_text = tail.decode("utf-8", errors="ignore")
                        except Exception:
                            tail_text = ""

                        # Only look at the last line-ish to avoid accidental matches
                        last_line = tail_text.splitlines()[-1] if tail_text.splitlines() else tail_text
                        for pat, reply in AUTO_REPLY_RULES:
                            if pat.search(last_line.strip()):
                                os.write(master_fd, reply.encode("utf-8"))
                                break

            # process exit?
            ret = proc.poll()
            if ret is not None:
                return ret, False, time.time() - start

        # timeout path: terminate group
        _kill_process_group(pgid, signal.SIGTERM, grace_seconds=5.0)
        _kill_process_group(pgid, signal.SIGKILL, grace_seconds=1.0)
        ret = proc.poll()
        return ret, True, time.time() - start
    finally:
        try:
            os.close(slave_fd)
        except Exception:
            pass
        try:
            os.close(master_fd)
        except Exception:
            pass


def _default_claude_cmd() -> list[str]:
    # Try to be flexible: user can pass `--claude-cmd "claude"` or "claude code"
    env = os.environ.get("CLAUDE_CMD", "").strip()
    if env:
        return shlex.split(env)
    return ["claude"]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Batch-run Claude Code sessions with per-port prompt templating and 20min timeout."
    )
    ap.add_argument(
        "--ports",
        required=True,
        help="Port list, comma/space separated. Example: --ports '8000,8001 8002'",
    )
    ap.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-session timeout seconds (default 1200).",
    )
    ap.add_argument(
        "--claude-cmd",
        default=None,
        help="Claude command (default from $CLAUDE_CMD or 'claude'). Example: --claude-cmd 'claude' or 'claude code'",
    )
    ap.add_argument(
        "--no-auto-reply",
        action="store_true",
        help="Disable auto-reply to interactive questions.",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Do not stream Claude output to stdout.",
    )
    args = ap.parse_args(argv)

    ports = _parse_ports(args.ports)
    if not ports:
        print("No ports provided.", file=sys.stderr)
        return 2

    claude_cmd = shlex.split(args.claude_cmd) if args.claude_cmd else _default_claude_cmd()

    results: list[SessionResult] = []
    for port in ports:
        prompt = "你可以尝试渗透一下http://222.20.126.52:{port}/，注意一定不能访问这个域名下的其他端口，安装的渗透工具你可以随意使用".format(port=port)
        print(f"\n=== session port={port} timeout={args.timeout_seconds}s cmd={shlex.join(claude_cmd)} ===", flush=True)

        exit_code, timed_out, elapsed = run_one_session(
            claude_cmd=claude_cmd,
            prompt=prompt,
            timeout_seconds=args.timeout_seconds,
            auto_reply=(not args.no_auto_reply),
            print_io=(not args.quiet),
        )
        results.append(
            SessionResult(
                port=str(port),
                exit_code=exit_code,
                timed_out=timed_out,
                elapsed_seconds=elapsed,
            )
        )

        status = "TIMEOUT" if timed_out else f"EXIT({exit_code})"
        print(f"\n--- done port={port} status={status} elapsed={elapsed:.1f}s ---", flush=True)

    print("\n=== summary ===")
    for r in results:
        status = "TIMEOUT" if r.timed_out else f"EXIT({r.exit_code})"
        print(f"port={r.port}\t{status}\telapsed={r.elapsed_seconds:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
