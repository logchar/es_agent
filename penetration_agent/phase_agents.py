# coding:utf-8
"""
单Agent模块：掌握所有工具的统一代理
"""
import logging
import asyncio
import time
from typing import Dict, List, Any
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
# 同 `claude_code_runner.py`：确保本进程读取到最新 `.env` 配置
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)

# Claude Code backend (CLI)
from claude_code_runner import run_claude_code

# from tools import HexStrikeClient
from storage import get_current_usage_tracker, get_current_target_url, ChallengeContext
from logging_config import get_logger, log_phase_start, log_phase_end, log_llm_request, log_llm_response

# 使用新的结构化日志系统
logger = get_logger("single_agent")

# ========================================
# 单Agent模式 - 统一代理
# ========================================

class SingleAgent:
    """单Agent模式 - 掌握所有工具的统一代理"""

    def __init__(self):
        self.name = "UnifiedAgent"
        self.description = "单Agent模式：掌握所有MCP工具，统一执行所有渗透测试任务"
        self.all_tools = []
        self.results = []

    async def execute(self, instruction: str, context: Dict[str, Any] = None):
        """执行单Agent任务。对话步数/轮次由 Claude Code 侧 ``CLAUDE_CODE_MAX_TURNS`` 控制，此处只发起一次子进程。"""
        logger.info(f"[单Agent] 开始执行: {instruction[:100]}...")

        target_url = context.get("target_url", "") if context else ""
        challenge_code = context.get("challenge_code", "") if context else ""
        # 如果调用方未显式传入，则从全局题目上下文补齐
        if not target_url:
            try:
                target_url = ChallengeContext.get_target_url() or ""
            except Exception:
                target_url = ""
        if not challenge_code:
            try:
                challenge_code = ChallengeContext.get_challenge_code() or ""
            except Exception:
                challenge_code = ""

        system_prompt = f"""
    你在参加CTF比赛，作为CTF渗透测试执行代理，目标是在授权边界内高效获取Flag。
    目标：{target_url}

    执行规则：
    1. 每一步遵循“推理-计划-行动”，行动后立即基于结果更新假设。
    2. 禁止线性扫全工具；必须机会主义：出现高价值线索就立刻转向利用。
    3. 仅在有触发条件时使用重型工具：
       - 发现明确技术栈/CMS/框架后再跑 nuclei。
       - 发现可疑参数（id/user/search/file/page/path）后再跑 sqlmap/dotdotpwn。
       - 发现输入点后再跑 XSS/爆破类工具。
    4. 自动化失败时优先切换 http_repeater 做精细验证与绕过。
    5. 工具输出是线索不是结论：必须提炼可执行下一步，不做重复低价值动作。
    6. 优先保留和扩展高价值资产：端点、参数、凭据、会话、可疑响应差异。
    7. 一旦发现疑似flag或关键敏感数据，立即验证并返回证据。
    """

        try:
            result = await self._run_claude_code_session(
                system_prompt=system_prompt,
                instruction=instruction,
                challenge_code=challenge_code,
            )

            await self._log_execution(instruction, True, "完成一次 Claude Code 子进程（轮次见 CLAUDE_CODE_MAX_TURNS）")
            return result

        except Exception as e:
            logger.error(f"[单Agent] 执行失败: {e}")
            await self._log_execution(instruction, False, str(e))
            return None

    async def _get_all_tools(self) -> List[Dict[str, Any]]:
        """获取所有工具"""
        # 说明：在 Claude Code 后端下，工具调用/权限/记忆均由 Claude Code 内部处理。
        # Python 侧不再加载/枚举 MCP 工具，以确保不会出现“双调度”。
        return []

    async def initialize(self):
        """异步初始化 - 获取所有工具"""
        self.all_tools = await self._get_all_tools()
        logger.debug(f"[单Agent] 已注册 {len(self.all_tools)} 个工具")

    def get_all_tools(self) -> List:
        """获取所有可用工具"""
        return self.all_tools

    async def _log_execution(self, instruction: str, success: bool, details: str = ""):
        """记录执行日志"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": self.name,
            "instruction": instruction,
            "success": success,
            "details": details
        }
        self.results.append(log_entry)
        logger.info(f"[单Agent: {self.name}] 执行完成 - {'成功' if success else '失败'}")

    # 简化版本：删除消息总结功能
    # 保留方法以避免破坏性更改，但不做任何事情
    pass

    def _truncate_text(self, text: Any, max_chars: int = 1000) -> str:
        """截断文本，避免消息上下文过大。"""
        text_str = str(text) if text is not None else ""
        if len(text_str) <= max_chars:
            return text_str
        return f"{text_str[:max_chars]}\n...[truncated {len(text_str) - max_chars} chars]"

    def _summarize_messages(self, history: List[Dict[str, Any]], max_chars: int = 3000) -> str:
        """本地压缩历史对话，保留关键动作与结果。"""
        if not history:
            return ""

        summary_lines: List[str] = ["历史摘要（压缩）:"]
        for msg in history:
            role = msg.get("role")
            if role == "assistant":
                tool_calls = msg.get("tool_calls") or []
                if tool_calls:
                    names = []
                    for call in tool_calls[:6]:
                        fn = call.get("function", {})
                        name = fn.get("name", "unknown_tool")
                        names.append(name)
                    summary_lines.append(f"- assistant 调用了工具: {', '.join(names)}")
            elif role == "tool":
                name = msg.get("name", "unknown_tool")
                content = self._truncate_text(msg.get("content", ""), 220).replace("\n", " ")
                summary_lines.append(f"- {name} 结果: {content}")

        summary = "\n".join(summary_lines)
        return self._truncate_text(summary, max_chars)

    async def _run_claude_code_session(
        self, system_prompt: str, instruction: str, challenge_code: str
    ) -> str:
        """单次 ``claude -p`` 会话；agent 轮次由环境变量 ``CLAUDE_CODE_MAX_TURNS`` 限制，不再在 Python 侧 for 循环多轮 continue。"""
        import re

        base_user_instruction = (instruction or "").strip()
        target_url = instruction.split("目标: ")[1].split("\n")[0] if "目标: " in instruction else ""
        log_phase_start(0, self.name, target_url)

        model_name = (os.getenv("CLAUDE_CODE_MODEL") or "ClaudeCode").strip() or "ClaudeCode"

        def _flag_found(text: str) -> bool:
            flag_patterns = [
                r"flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
                r"FLAG\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
            ]
            for pattern in flag_patterns:
                if re.search(pattern, text or "", re.IGNORECASE):
                    return True
            return False

        claude_prompt = (
            f"[SYSTEM]\n{system_prompt.strip()}\n\n"
            f"[USER]\n{base_user_instruction}\n"
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": base_user_instruction},
        ]
        # max_rounds 字段仅作结构化日志用：Python 侧固定为 1 次子进程
        log_llm_request(messages, model_name, 0, 1, challenge_code)

        result = await run_claude_code(
            prompt=claude_prompt,
            cwd=os.getcwd(),
            continue_session=False,
            challenge_code=challenge_code,
        )

        response_obj = {
            "backend": "claude_code",
            "model": model_name,
            "round": 1,
            "continue_session": False,
            "note": "agent 轮次由 CLAUDE_CODE_MAX_TURNS 控制",
            "cwd": os.getcwd(),
            "ok": result.ok,
            "exit_code": result.exit_code,
            "duration_s": result.duration_s,
            "cmd": result.cmd,
            "stdout_preview": (result.stdout or "")[:2000],
            "stderr_preview": (result.stderr or "")[:2000],
        }

        usage_tracker = get_current_usage_tracker()
        if usage_tracker:
            usage_tracker.log_agent_usage(
                {
                    "provider": "claude_code",
                    "model": model_name,
                    "round": 1,
                    "exit_code": result.exit_code,
                    "duration_s": result.duration_s,
                    "stdout_chars": len(result.stdout or ""),
                    "stderr_chars": len(result.stderr or ""),
                },
                get_current_target_url(),
            )

        log_llm_response(response_obj, 0, 0, challenge_code)

        output_text = (result.stdout or "").strip()
        err_text = (result.stderr or "").strip()

        if not output_text and err_text:
            output_text = err_text
        if not output_text and not err_text:
            output_text = f"[claude_code] empty output (exit_code={result.exit_code}, ok={result.ok})"
        if not result.ok and err_text and err_text not in output_text:
            output_text = f"{output_text}\n\n[claude_code stderr]\n{err_text}"

        if _flag_found(output_text):
            logger.info(f"[单Agent: {self.name}] 在Claude Code输出中发现疑似flag")
            log_phase_end(0, self.name, True, len(self.results))
            return output_text

        if not result.ok:
            log_phase_end(0, self.name, False, len(self.results))
            return output_text

        log_phase_end(0, self.name, True, len(self.results))
        return output_text


# ========================================
# 单Agent阶段管理器
# ========================================

class PhaseManager:
    """单Agent阶段管理器 - 协调单Agent执行"""

    def __init__(self):
        self.single_agent = None
        self.findings = []  # 跨阶段的发现
        logger.debug("PhaseManager 初始化完成")

    @classmethod
    async def create_single_agent(cls):
        """
        异步创建并初始化单Agent PhaseManager 实例
        """
        logger.debug("开始创建单Agent PhaseManager...")
        instance = cls()

        # Claude Code 将自行管理工具调用；Python 侧不启动 MCP 客户端。
        logger.info("使用 Claude Code 工具管理")

        # 创建单一agent
        instance.single_agent = SingleAgent()
        await instance.single_agent.initialize()
        logger.info(f"单Agent初始化完成，包含 {len(instance.single_agent.all_tools)} 个工具")

        logger.debug("单Agent PhaseManager 创建完成")
        return instance

    async def execute_single_agent(self, instruction: str, context: Dict[str, Any] = None):
        """使用单Agent统一执行任务 - 使用ChallengeContext确保上下文隔离。轮次仅由 ``CLAUDE_CODE_MAX_TURNS`` 限制。"""
        if not self.single_agent:
            raise ValueError("未初始化单agent")

        # 获取当前题目信息
        challenge_code = ChallengeContext.get_challenge_code()
        target_url = ChallengeContext.get_target_url()

        logger.info(f"使用单Agent统一执行任务 - 题目: {challenge_code}")

        # 添加上下文信息（使用ChallengeContext确保隔离）
        if context is None:
            context = {}
        context["previous_findings"] = ChallengeContext.get_findings()

        # 执行单agent
        result = await self.single_agent.execute(instruction, context)

        # 将结果添加到ChallengeContext
        if result:
            ChallengeContext.add_finding({
                "phase": 0,
                "phase_name": "UnifiedAgent",
                "result": result,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        return result

    def get_all_summaries(self) -> Dict[str, Any]:
        """获取执行总结 - 从ChallengeContext获取"""
        # 从ChallengeContext获取当前题目的摘要
        context_summary = ChallengeContext.get_context_summary()

        return {
            "agent": self.single_agent.name,
            "challenge_code": context_summary.get("challenge_code"),
            "target_url": context_summary.get("target_url"),
            "total_rounds": len(self.single_agent.results),
            "successful_rounds": sum(1 for r in self.single_agent.results if r["success"]),
            "failed_rounds": sum(1 for r in self.single_agent.results if not r["success"]),
            "results": self.single_agent.results,
            "context_summary": context_summary
        }
