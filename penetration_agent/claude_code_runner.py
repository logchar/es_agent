# coding:utf-8
"""Claude Code CLI runner.

本模块已重构为优先使用 Claude SDK（`claude_code_sdk` / `claude_agent_sdk`）运行，
不再手动 spawn `claude -p` 子进程。

仍然支持“限制轮数”与“可控 session 日志落盘路径”，并与旧环境变量保持兼容。

全部通过 **环境变量**（含 ``penetration_agent/.env``）配置，本模块**不接受** max_turns / export
  的函数参数。

Environment variables:
- `CLAUDE_SDK_MODEL` / `CLAUDE_CODE_MODEL`: Claude 模型（优先读 `CLAUDE_SDK_MODEL`）
- `CLAUDE_SDK_MAX_TURNS` / `CLAUDE_CODE_MAX_TURNS`: 轮数上限（优先读 `CLAUDE_SDK_MAX_TURNS`）
- `CLAUDE_SDK_PERMISSION_MODE`: SDK permission_mode（default/acceptEdits/plan/bypassPermissions）
- `CLAUDE_SDK_ALLOWED_TOOLS` / `CLAUDE_CODE_ALLOWED_TOOLS`: 允许工具（空格分隔；可选）
- `CLAUDE_SDK_DISALLOWED_TOOLS`: 禁止工具（空格分隔；可选）
- `CLAUDE_SDK_CWD`: 会话工作目录（默认：传入 run_claude_code 的 cwd 或当前进程 cwd）
- `CLAUDE_SDK_SETTINGS`: Claude Code settings 文件路径（可选）
- `CLAUDE_SDK_MCP_CONFIG` / `CLAUDE_CODE_MCP_CONFIG`: MCP 配置（路径或 JSON 字符串；可选）
- `CLAUDE_SDK_SESSION_ID`: session_id（默认：default）
- `CLAUDE_SDK_SESSION_LOG_FILE`: 若设置，将 SDK message 流以 JSONL 形式写入该路径（推荐）
- `CLAUDE_CODE_EXPORT_FILE`: 兼容旧行为：将本次会话的“可观测输出摘要”写入纯文本路径

以上可写在**与本文件同目录**的 ``.env`` 中；模块导入时 ``load_dotenv(..., override=False)``。
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
import traceback
from datetime import datetime, timezone

from dotenv import load_dotenv

_load_dir = os.path.dirname(os.path.abspath(__file__))
# 注意：本模块的行为高度依赖 `.env`；为避免“旧环境变量已存在但为空字符串”导致新配置无法生效，
# 这里对本模块使用 override=True（只影响本进程环境，不会写回系统环境）。
load_dotenv(dotenv_path=os.path.join(_load_dir, ".env"), override=True)

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ClaudeCodeResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    cmd: List[str]
    """主任务命令行（argv 列表）。"""
    export_path: Optional[str] = None
    """若配置了 ``CLAUDE_CODE_EXPORT_FILE``，为写出路径。"""
    export_ok: Optional[bool] = None
    """是否成功写入导出文件（Python 写盘）。"""
    export_cmd: List[str] = field(default_factory=list)
    """已废弃为二次 claude 调用；保留空列表。导出由本模块直接写文件。"""
    export_stdout: str = ""
    export_stderr: str = ""
    export_duration_s: float = 0.0
    """写导出文件所耗秒数（极小）。"""
    session_id: Optional[str] = None
    """SDK session id（若可获取）。"""
    session_log_path: Optional[str] = None
    """若配置了 ``CLAUDE_SDK_SESSION_LOG_FILE``，为写出路径。"""
    session_log_ok: Optional[bool] = None
    """是否成功写入 session JSONL 日志。"""


def _env_flag(name: str) -> bool:
    value = (os.getenv(name) or "").strip().lower()
    return value in {"1", "true", "yes", "y", "on"}


def _int_from_env(*names: str) -> Optional[int]:
    raw = ""
    for n in names:
        raw = (os.getenv(n) or "").strip()
        if raw:
            break
    if not raw:
        return None
    try:
        n = int(raw, 10)
        return n if n > 0 else None
    except ValueError:
        return None


def _export_path_from_env() -> Optional[str]:
    p = (os.getenv("CLAUDE_CODE_EXPORT_FILE") or "").strip()
    if not p:
        return None
    p = os.path.abspath(p)
    parent = os.path.dirname(p) or "."
    os.makedirs(parent, exist_ok=True)
    return p


def _sdk_session_log_path_from_env() -> Optional[str]:
    p = (os.getenv("CLAUDE_SDK_SESSION_LOG_FILE") or "").strip()
    if not p:
        return None
    p = os.path.abspath(p)
    parent = os.path.dirname(p) or "."
    os.makedirs(parent, exist_ok=True)
    return p


def _sdk_debug_path_from_env() -> Optional[str]:
    p = (os.getenv("CLAUDE_SDK_DEBUG_FILE") or "").strip()
    if not p:
        return None
    p = os.path.abspath(p)
    parent = os.path.dirname(p) or "."
    os.makedirs(parent, exist_ok=True)
    return p


def _write_text(path: str, text: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
        return True
    except OSError:
        return False


def _maybe_sanitize_settings_path(settings_path: Optional[str], debug_lines: list[str]) -> Optional[str]:
    """
    若 CLAUDE_SDK_SANITIZE_SETTINGS=1，则尝试生成一个“瘦身后的 settings”，
    以规避 Windows/跨平台 settings 中的插件/marketplace 路径导致初始化卡死/失败。
    """
    if not settings_path:
        return None
    if not _env_flag("CLAUDE_SDK_SANITIZE_SETTINGS"):
        return settings_path

    try:
        with open(settings_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        data = json.loads(raw)
    except Exception as e:
        debug_lines.append(f"[settings] sanitize skipped: cannot parse json ({type(e).__name__}: {e})")
        return settings_path

    # 记录一些“高危字段”以便排查
    try:
        enabled_plugins = data.get("enabledPlugins")
        extra_market = data.get("extraKnownMarketplaces")
        if enabled_plugins:
            debug_lines.append(f"[settings] enabledPlugins keys: {list(enabled_plugins.keys())[:50]}")
        if extra_market:
            debug_lines.append(f"[settings] extraKnownMarketplaces keys: {list(extra_market.keys())[:50]}")
    except Exception:
        pass

    removed: list[str] = []
    for k in ["enabledPlugins", "extraKnownMarketplaces"]:
        if k in data:
            data.pop(k, None)
            removed.append(k)
    if removed:
        debug_lines.append(f"[settings] sanitized: removed {', '.join(removed)}")

    out_path = os.path.abspath(os.path.join(os.path.dirname(settings_path), "claude-settings.sanitized.json"))
    try:
        with open(out_path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        debug_lines.append(f"[settings] sanitized_settings_path: {out_path}")
        return out_path
    except OSError as e:
        debug_lines.append(f"[settings] sanitize failed to write ({type(e).__name__}: {e})")
        return settings_path


def _write_export_transcript(
    path: str,
    main_cmd: List[str],
    exit_code: int,
    duration_s: float,
    stdout: str,
    stderr: str,
) -> bool:
    """
    兼容旧行为：将“可观测输出摘要”写入纯文本。
    """
    ts = datetime.now(timezone.utc).isoformat()
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write("Claude SDK 运行记录（本文件由 es_agent 写入；内容为摘要，并非 Claude Code TUI /export）\n")
            f.write(f" written_at_utc: {ts}\n")
            f.write(f" exit_code: {exit_code}\n")
            f.write(f" duration_s: {duration_s:.3f}\n\n")
            f.write("=== argv (main) ===\n")
            f.write(" ".join(shlex.quote(c) for c in main_cmd))
            f.write("\n\n=== stdout ===\n")
            f.write(stdout or "")
            f.write("\n\n=== stderr ===\n")
            f.write(stderr or "")
            f.write("\n")
        return True
    except OSError:
        return False


def _split_tools(raw: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    return shlex.split(raw)


def _build_pseudo_cmd(prompt: str, *, continue_session: bool) -> list[str]:
    """为结构化日志保留一个“类似命令行”的描述，避免破坏上层日志字段。"""
    model = (os.getenv("CLAUDE_SDK_MODEL") or os.getenv("CLAUDE_CODE_MODEL") or "").strip()
    max_turns = _int_from_env("CLAUDE_SDK_MAX_TURNS", "CLAUDE_CODE_MAX_TURNS")
    permission_mode = (os.getenv("CLAUDE_SDK_PERMISSION_MODE") or "").strip()
    cmd = ["claude_sdk"]
    if model:
        cmd += ["--model", model]
    if max_turns is not None:
        cmd += ["--max-turns", str(max_turns)]
    if permission_mode:
        cmd += ["--permission-mode", permission_mode]
    if continue_session:
        cmd.append("--continue")
    cmd.append(prompt)
    return cmd


def _write_session_jsonl(path: str, entries: list[dict]) -> bool:
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            for e in entries:
                # 兜底：确保任何对象都可序列化（例如 SDK 的 TextBlock 等）
                f.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
        return True
    except OSError:
        return False


def _sanitize_path_component(value: str, max_len: int = 120) -> str:
    """将任意字符串安全化为文件名组件，避免出现 '/', ':' 等导致路径错误的字符。"""
    if not value:
        return ""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))
    safe = safe.strip("_ .-")
    if len(safe) > max_len:
        safe = safe[:max_len].rstrip("_ .-")
    return safe


def _derive_log_path(base_path: str, *, challenge_code: str, model_name: Optional[str], ts: str) -> str:
    """
    从环境变量给出的“基准文件”派生出不会覆盖的新路径：
    - 保留同目录
    - 以 challenge/model/timestamp 作为前缀
    - 原文件名作为后缀（便于人类识别用途）
    """
    base_path = os.path.abspath(base_path)
    parent = os.path.dirname(base_path) or "."
    base_name = os.path.basename(base_path)
    cc = _sanitize_path_component(challenge_code)
    mn = _sanitize_path_component(model_name or "")
    prefix = "_".join([p for p in [cc, mn, ts] if p])
    out = os.path.join(parent, f"{prefix}_{base_name}")
    os.makedirs(parent, exist_ok=True)
    return out


async def run_claude_code(
    prompt: str,
    cwd: Optional[str] = None,
    timeout_s: Optional[int] = None,
    continue_session: bool = False,
    challenge_code: str = "",
) -> ClaudeCodeResult:
    export_path = _export_path_from_env()
    session_log_path = _sdk_session_log_path_from_env()

    # 若传入 challenge_code，则基于环境变量给的“基准路径”派生不覆盖的路径
    if challenge_code:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        model_for_name = (os.getenv("CLAUDE_SDK_MODEL") or os.getenv("CLAUDE_CODE_MODEL") or "").strip() or None

        if session_log_path is not None:
            session_log_path = _derive_log_path(
                session_log_path, challenge_code=challenge_code, model_name=model_for_name, ts=ts
            )
        if export_path is not None:
            export_path = _derive_log_path(
                export_path, challenge_code=challenge_code, model_name=model_for_name, ts=ts
            )

    debug_path = _sdk_debug_path_from_env()

    # 由于上层日志中仍引用 `cmd` 字段，这里保留一个伪 argv
    main_cmd = _build_pseudo_cmd(prompt, continue_session=continue_session)

    # SDK 调用（优先 claude_agent_sdk，新旧包名兼容）
    start = time.time()
    out_text = ""
    err_text = ""
    exit_code = 0
    session_id: Optional[str] = None
    session_entries: list[dict] = []
    debug_lines: list[str] = []

    model = (os.getenv("CLAUDE_SDK_MODEL") or os.getenv("CLAUDE_CODE_MODEL") or "").strip() or None
    max_turns = _int_from_env("CLAUDE_SDK_MAX_TURNS", "CLAUDE_CODE_MAX_TURNS")
    permission_mode = (os.getenv("CLAUDE_SDK_PERMISSION_MODE") or "").strip() or None
    allowed_tools = _split_tools(os.getenv("CLAUDE_SDK_ALLOWED_TOOLS") or os.getenv("CLAUDE_CODE_ALLOWED_TOOLS") or "")
    disallowed_tools = _split_tools(os.getenv("CLAUDE_SDK_DISALLOWED_TOOLS") or "")
    # Claude Code settings.json 路径：优先 CLAUDE_SDK_SETTINGS，其次兼容 CLAUDE_CODE_SETTINGS
    settings = (os.getenv("CLAUDE_SDK_SETTINGS") or os.getenv("CLAUDE_CODE_SETTINGS") or "").strip() or None
    # 预检：settings 不可读（常见：/mnt/c/... EPERM）则不传，避免初始化阶段直接炸
    if settings:
        try:
            with open(settings, "rb"):
                pass
        except OSError as e:
            debug_lines.append(f"[settings] unreadable, fallback to None ({type(e).__name__}: {e})")
            settings = None
    debug_lines.append(f"[runner] settings_path_after_read_check: {settings!r}")
    settings = _maybe_sanitize_settings_path(settings, debug_lines)
    debug_lines.append(f"[runner] settings_path_after_sanitize: {settings!r}")

    mcp_config = (os.getenv("CLAUDE_SDK_MCP_CONFIG") or os.getenv("CLAUDE_CODE_MCP_CONFIG") or "").strip() or None
    session_id = (os.getenv("CLAUDE_SDK_SESSION_ID") or "").strip() or "default"
    sdk_cwd = (os.getenv("CLAUDE_SDK_CWD") or "").strip() or (cwd or os.getcwd())

    # 注意：claude_code_sdk / claude_agent_sdk 内部仍可能依赖 bundled CLI，
    # 但对本项目侧来说已经是“SDK 调用形态”（无需手写子进程管理/argv）。
    try:
        try:
            from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions  # type: ignore
            OptionsType = ClaudeAgentOptions  # noqa: N806
            debug_lines.append("[runner] sdk_import: claude_agent_sdk")
        except Exception:
            from claude_code_sdk import ClaudeSDKClient, ClaudeCodeOptions  # type: ignore
            OptionsType = ClaudeCodeOptions  # noqa: N806
            debug_lines.append("[runner] sdk_import: claude_code_sdk")

        options = OptionsType(
            model=model,
            max_turns=max_turns,
            permission_mode=permission_mode,
            allowed_tools=allowed_tools,
            disallowed_tools=disallowed_tools,
            cwd=sdk_cwd,
            settings=settings,
            mcp_servers=mcp_config or {},  # 支持路径/JSON 字符串；为空则用默认
        )
        debug_lines.append(
            f"[runner] options: model={model!r} max_turns={max_turns!r} permission_mode={permission_mode!r} cwd={str(sdk_cwd)!r}"
        )
        debug_lines.append(f"[runner] allowed_tools={allowed_tools!r} disallowed_tools={disallowed_tools!r}")
        debug_lines.append(f"[runner] mcp_config_set={bool(mcp_config)} session_id={session_id!r}")
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt, session_id=session_id)

            # 收集本次 response 的消息流
            assistant_text_parts: list[str] = []
            async for msg in client.receive_response():
                # 记录 session 日志（尽可能结构化；避免依赖内部对象序列化）
                entry = {
                    "ts_utc": datetime.now(timezone.utc).isoformat(),
                    "session_id": getattr(msg, "session_id", session_id),
                    "type": msg.__class__.__name__,
                }
                # ResultMessage: cost/turns/result 等
                if hasattr(msg, "__dict__"):
                    # 只保留浅层字段，避免不可 JSON 的对象
                    for k, v in msg.__dict__.items():
                        if k in {"content", "result", "usage", "total_cost_usd", "num_turns", "duration_ms", "is_error", "model", "subtype"}:
                            try:
                                # 注意：不能把原始对象（如 TextBlock）塞进去，否则写 JSONL 时会炸。
                                # 这里用 json round-trip 把数据“彻底 JSON 化”，非 JSON 对象会被 str()。
                                entry[k] = json.loads(json.dumps(v, ensure_ascii=False, default=str))
                            except Exception:
                                entry[k] = str(v)
                session_entries.append(entry)

                # 尝试抽取 assistant 文本
                if hasattr(msg, "content"):
                    content = getattr(msg, "content")
                    # content 可能是 list[ContentBlock]
                    if isinstance(content, list):
                        for block in content:
                            # TextBlock: .text
                            if hasattr(block, "text"):
                                assistant_text_parts.append(str(getattr(block, "text")))
                            # 兼容直接是 dict / str 的情况
                            elif isinstance(block, dict) and block.get("type") == "text":
                                assistant_text_parts.append(str(block.get("text", "")))
                    elif isinstance(content, str):
                        assistant_text_parts.append(content)

                # ResultMessage: 若有 result 字段也纳入输出
                if hasattr(msg, "result") and getattr(msg, "result") and not assistant_text_parts:
                    assistant_text_parts.append(str(getattr(msg, "result")))

                if hasattr(msg, "is_error") and getattr(msg, "is_error"):
                    exit_code = 1

            out_text = "\n".join([p for p in assistant_text_parts if p]).strip()

    except Exception as e:
        exit_code = 1
        tb = traceback.format_exc()
        hint = ""
        if isinstance(e, ModuleNotFoundError):
            # 这类错误最常见：当前 Python 环境未安装 claude-agent-sdk（或装在另一个解释器里）
            hint = (
                "\n\n[hint]\n"
                "当前 Python 环境未找到 Claude SDK 包。请确保在运行 `python penetration_agent/main.py` 的同一解释器下安装：\n"
                "  python -m pip install --user claude-agent-sdk\n"
                "或使用虚拟环境/conda 环境安装后再运行。\n"
            )
        err_text = f"[claude_sdk] {type(e).__name__}: {e}{hint}\n\n{tb}"
        debug_lines.append("[runner] exception:")
        debug_lines.append(tb)

    dur = time.time() - start
    main_ok = exit_code == 0

    if debug_path is not None:
        _write_text(
            debug_path,
            "\n".join(
                [
                    f"written_at_utc: {datetime.now(timezone.utc).isoformat()}",
                    f"duration_s: {dur:.3f}",
                    f"exit_code: {exit_code}",
                    f"pseudo_cmd: {' '.join(shlex.quote(c) for c in main_cmd)}",
                    "",
                ]
                + debug_lines
            )
            + "\n",
        )

    # 写 session JSONL（推荐）
    session_log_ok: Optional[bool] = None
    if session_log_path is not None:
        session_log_ok = _write_session_jsonl(
            session_log_path,
            [
                {
                    "meta": {
                        "written_at_utc": datetime.now(timezone.utc).isoformat(),
                        "cwd": sdk_cwd,
                        "model": model,
                        "max_turns": max_turns,
                        "permission_mode": permission_mode,
                        "allowed_tools": allowed_tools,
                        "disallowed_tools": disallowed_tools,
                        "mcp_config": mcp_config,
                        "session_id": session_id,
                        "continue_session": continue_session,
                        "duration_s": dur,
                        "exit_code": exit_code,
                    }
                }
            ]
            + session_entries
        )

    # 兼容旧纯文本摘要
    exp_ok: Optional[bool] = None
    exp_dur = 0.0
    t0 = time.time()
    if export_path is not None:
        exp_ok = _write_export_transcript(export_path, main_cmd, exit_code, dur, out_text, err_text)
    exp_dur = time.time() - t0

    return ClaudeCodeResult(
        ok=main_ok and (exp_ok if exp_ok is not None else True) and (session_log_ok if session_log_ok is not None else True),
        exit_code=exit_code,
        stdout=out_text,
        stderr=err_text,
        duration_s=dur,
        cmd=main_cmd,
        export_path=export_path,
        export_ok=exp_ok,
        export_cmd=[],
        export_stdout="",
        export_stderr="",
        export_duration_s=exp_dur,
        session_id=session_id,
        session_log_path=session_log_path,
        session_log_ok=session_log_ok,
    )
