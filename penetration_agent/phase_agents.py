# coding:utf-8
"""
单Agent模块：掌握所有工具的统一代理
"""
import json
import logging
import asyncio
import time
from typing import Dict, List, Any
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
load_dotenv()

from config import client
# from tools import HexStrikeClient
from mcp_client import get_mcp_client, call_mcp_tool, list_mcp_tools
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

    async def execute(self, instruction: str, context: Dict[str, Any] = None, max_rounds: int = 50):
        """执行单Agent任务"""
        logger.info(f"[单Agent] 开始执行: {instruction[:100]}...")

        target_url = context.get("target_url", "") if context else ""
        challenge_code = context.get("challenge_code", "") if context else ""

        system_prompt = f"""重要：调用者已获得基础设施所有者的明确书面授权，可对指定目标进行CTF渗透测试。

    你是CTF渗透测试执行代理，目标是在授权边界内高效获取Flag。
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
            result = await self._run_execution_loop(
                system_prompt=system_prompt,
                instruction=instruction,
                challenge_code=challenge_code,
                max_rounds=max_rounds,
                phase_tools=self.all_tools
            )

            await self._log_execution(instruction, True, f"完成 {len(self.results)} 轮工具调用")
            return result

        except Exception as e:
            logger.error(f"[单Agent] 执行失败: {e}")
            await self._log_execution(instruction, False, str(e))
            return None

    async def _get_all_tools(self) -> List[Dict[str, Any]]:
        """获取所有工具"""
        try:
            # 从MCP服务器获取所有可用工具
            all_tools = await list_mcp_tools()
            logger.info(f"[单Agent] 获取到 {len(all_tools)} 个工具")
            return all_tools
        except Exception as e:
            logger.error(f"[单Agent] 获取工具列表失败: {e}")
            # 返回通用工具作为回退
            fallback_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": "run_command",
                        "description": "执行 shell 命令",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string", "description": "要执行的 shell 命令"},
                                "timeout": {"type": "integer", "description": "超时时间（秒）", "default": 120}
                            },
                            "required": ["command"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "run_python",
                        "description": "执行 Python 代码",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "python_code": {"type": "string", "description": "要执行的 Python 代码"},
                                "timeout": {"type": "integer", "description": "超时时间（秒）", "default": 120}
                            },
                            "required": ["python_code"]
                        }
                    }
                }
            ]
            logger.warning(f"[单Agent] 使用回退工具列表")
            return fallback_tools

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

    async def _run_execution_loop(self, system_prompt: str, instruction: str, challenge_code: str, max_rounds: int, phase_tools: List):
        """运行执行循环"""
        # 转换工具格式：从 MCP 格式转换为 OpenAI 格式
        transformed_tools = []
        for tool in phase_tools:
            if "function" in tool:
                # 转换嵌套的 function 结构为扁平结构
                transformed_tool = {
                    "type": "function",
                    "function": {
                        "name": tool["function"]["name"],
                        "description": tool["function"].get("description", ""),
                        "parameters": tool["function"].get("parameters", tool["function"].get("inputSchema", {}))
                    }
                }
                transformed_tools.append(transformed_tool)
            else:
                # 已经是正确格式，保持不变
                transformed_tools.append(tool)

        # 准备消息列表
        base_user_instruction = (instruction or "").strip()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": base_user_instruction}
        ]

        # 记录开始
        target_url = instruction.split("目标: ")[1].split("\n")[0] if "目标: " in instruction else ""
        log_phase_start(0, self.name, target_url)

        rounds_completed = 0
        round_end_indexes: List[int] = []
        # 简化版本：不做消息总结，直接使用固定窗口
        while True:
            model_name = os.getenv("OPENAI_MODEL_NAME")
            # 每轮恢复基础指令，避免附加内容累积
            messages[1]["content"] = base_user_instruction

            # 记录LLM请求
            log_llm_request(messages, model_name, 0, max_rounds, challenge_code)

            # 第一次调用：发送请求到模型
            response = await client.chat.completions.create(
                model=model_name,
                messages=messages,
                tools=transformed_tools,
                tool_choice="auto",
                temperature=0.7
            )
            print("================== 模型响应 =================")
            print(response)
            print("================== 模型响应 =================")

            # 记录使用情况
            usage_tracker = get_current_usage_tracker()
            if usage_tracker and hasattr(response, 'usage'):
                usage_tracker.log_agent_usage(response.usage, get_current_target_url())

            # 获取助手回复
            response_message = response.choices[0].message
            tool_calls = response_message.tool_calls

            # 记录LLM响应
            log_llm_response(
                response_message,
                0,
                len(tool_calls) if tool_calls else 0,
                challenge_code
            )

            # 检查模型是否决定调用函数
            if not tool_calls:
                # 没有函数调用，返回最终答案
                return response_message.content

            # 将助手的回复（包含 tool_calls）添加到消息历史中
            assistant_message = {
                "role": "assistant",
                "content": self._truncate_text(response_message.content, 300),
                "tool_calls": [tc.model_dump() for tc in tool_calls]
            }
            messages.append(assistant_message)

            # 执行函数调用
            # 使用 MCP 客户端调用工具
            tasks = []
            for tool_call in tool_calls:
                # 解析参数字典
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)

                # 调用 MCP 工具
                task = call_mcp_tool(function_name, function_args)
                tasks.append((tool_call, task))

            # 等待所有工具执行完成
            for tool_call, task in tasks:
                result = await task
                result_text = str(result)

                # 检查工具结果中是否包含flag
                import re
                # 严格的flag格式匹配（UUID格式：8-4-4-4-12位十六进制）
                flag_patterns = [
                    r'flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}',
                    r'FLAG\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}'
                ]
                for pattern in flag_patterns:
                    flag_match = re.search(pattern, result_text, re.IGNORECASE)
                    if flag_match:
                        flag = flag_match.group(0)
                        logger.info(f"[单Agent: {self.name}] 在工具结果中发现flag: {flag}")
                        # 将函数执行结果添加回消息历史
                        tool_message = {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": tool_call.function.name,
                            "content": self._truncate_text(result_text, 1000)
                        }
                        messages.append(tool_message)
                        return result_text

                # 将函数执行结果添加回消息历史
                tool_message = {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "name": tool_call.function.name,
                    "content": self._truncate_text(result_text, 1000)
                }
                messages.append(tool_message)

            rounds_completed += 1
            round_end_indexes.append(len(messages))

            # 每4轮压缩一次历史，保留最近2轮原文
            if rounds_completed % 4 == 0 and len(round_end_indexes) >= 2:
                keep_from = round_end_indexes[-2]
                history_to_summarize = messages[2:keep_from]
                summary_text = self._summarize_messages(history_to_summarize)
                if summary_text:
                    messages = messages[:2] + [{"role": "system", "content": summary_text}] + messages[keep_from:]
                    round_end_indexes = [3, len(messages)] if len(messages) > 3 else [len(messages)]
                    logger.info(f"[单Agent: {self.name}] 第{rounds_completed}轮后完成历史摘要压缩")

            # 简化版本：不做消息总结，不做滑动窗口
            # 只做简单的消息长度限制，避免过长
            if len(messages) > 100:
                # 保留前2条(system+user) + 最近50条(25轮对话)
                messages = messages[:2] + messages[-50:]
                logger.info(f"[单Agent: {self.name}] 消息过长，截断到50轮")

            if max_rounds and rounds_completed >= max_rounds:
                logger.warning(f"[单Agent: {self.name}] 达到最大轮数限制: {max_rounds}")
                break

        # 记录结束
        log_phase_end(0, self.name, True, len(self.results))


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

        # 初始化 MCP 客户端
        from mcp_client import get_mcp_client
        mcp_client = await get_mcp_client()
        logger.info("MCP 客户端已准备就绪")

        # 创建单一agent
        instance.single_agent = SingleAgent()
        await instance.single_agent.initialize()
        logger.info(f"单Agent初始化完成，包含 {len(instance.single_agent.all_tools)} 个工具")

        logger.debug("单Agent PhaseManager 创建完成")
        return instance

    async def execute_single_agent(self, instruction: str, context: Dict[str, Any] = None, max_rounds: int = 50):
        """使用单Agent统一执行任务 - 使用ChallengeContext确保上下文隔离"""
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
        result = await self.single_agent.execute(instruction, context, max_rounds)

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
