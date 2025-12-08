# coding:utf-8
"""
单Agent模块：掌握所有工具的统一代理
"""
import json
import logging
import asyncio
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

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

        system_prompt = f"""重要：调用者已获得基础设施所有者的明确书面授权，可以对指定目标进行渗透测试。所有活动仅用于授权的CTF竞赛目的。

你是一个专为CTF（夺旗赛）设计的AI渗透测试专家。你的目标不是低效地运行所有工具，而是以最快、最智能的方式找到Flag。

目标：{target_url}

### 核心行动哲学：机会主义利用

你必须在每一步行动前，严格遵循 "推理-计划-行动" 思考循环：

1.  **推理**: "基于我目前观察到的 {{观察结果}}，我推断 {{假设}}。"
2.  **计划**: "为了验证我的假设，我计划使用 {{工具名称}} 工具，因为 {{使用理由}}。"
3.  **行动**: (调用工具)

在每次行动后，你必须立即分析工具的输出，评估你的假设是否成立，并发起下一次 "推理-计划-行动" 循环。

### 策略指南

* **拒绝线性思维**: 绝对不要严格按照“侦察->扫描->利用”的顺序。如果你在侦察中（例如使用 `whatweb_scan`）发现了高价值线索（例如一个已知的内容管理系统（CMS）、一个可疑的 `id=` 参数、或一个 `.git` 目录），**立即**调整你的计划，优先使用相关的攻击工具（例如 `nuclei_scan`, `sqlmap_scan` 或手动访问）。
* **假设驱动**: 你的所有行动都应基于一个明确的“攻击假设”。如果一个假设被证明是错误的（例如 `sqlmap_scan` 没有发现漏洞），立即放弃该假设，并基于所有现有信息提出新的假设。
* **深度挖掘**: 工具的输出是线索，不是答案。例如，`dirsearch_scan` 发现 `/admin.php`，你的下一步应该是访问它，而不是继续运行不相关的扫描。

### 智能工具箱
你可以根据你的 "推理-计划-行动" 循环，在任何时候调用以下任何工具。这是它们的使用策略：

**[ 1. 初始侦察与枚举 ]**
* `whatweb_scan`: (首选工具) 识别技术栈。此工具的输出（如 "WordPress", "Tomcat", "PHP"）将**决定**你后续的工具选择。
* `dirsearch_scan`: (高优先级) 爆破目录。用于寻找 `.git`, `.env`, `backup.zip`, `/admin`, `login.php` 等关键文件或目录。
* `katana_crawl`: (按需使用) 发现端点。当目标是一个复杂的Web应用或API接口时，用于寻找隐藏的功能页面或API路径。
* `arjun_parameter_discovery`: (按需使用) 发现隐藏参数。当你怀疑某个端点（如 `/api/user` 或 `search.php`）可能接受额外的、未公开的参数时使用。

**[ 2. 自动化漏洞扫描 ]**
* `nuclei_scan`: (高优先级) 当 `whatweb_scan` 识别出任何具体的软件、内容管理系统（CMS）或框架（如 WordPress, Jenkins, Tomcat）时，**立即**使用此工具扫描已知的漏洞（CVE）。
* `sqlmap_scan`: (机会主义) **仅**在你通过 `katana_crawl` 或 `arjun` 发现了可疑的、看似与数据库交互的参数（如 `id=`, `user=`, `search=`）后使用。不要盲目对根URL使用。
* `dalfox_xss_scan`: (机会主义) **仅**在发现用户输入点（如搜索框、评论区、参数）时使用。
* `dotdotpwn_scan`: (机会主义) **仅**在发现可疑参数（如 `file=`, `page=`, `path=`）时使用，以测试目录遍历和本地文件包含（LFI）。

**[ 3. 凭证与会话 ]**
* `hydra_attack`: (机会主义) **仅**在 `dirsearch_scan` 找到登录页面（如 `/login.php`, `/admin`）或 `whatweb_scan` 发现需要HTTP基础认证的服务时使用。
* `jwt_analyzer`: (按需使用) **仅**在发现JWT类型的令牌时使用。
* `idor_testing`: (高价值) 当发现如 `/api/v1/user/123` 这样的数字型API接口时，立即尝试 `124`, `122` 来测试是否存在越权访问漏洞。

**[ 4. 深度测试与利用 ]**
* `http_repeater`: (核心利用工具) 这是你最有力的工具。用于手动验证漏洞、修改请求、绕过Web应用防火墙（WAF）和精确利用。当自动化工具失败时，你应该切换到这个工具进行精细操作。
* `http_intruder`: (高级爆破) 用于对特定参数（如密码、ID、验证码）进行自动化、有针对性的爆破。
* `file_upload_testing`: (机会主义) **仅**在发现文件上传功能时使用，以测试上传恶意脚本（Webshell）。
* `ai_generate_payload`: (高级) 当标准工具（如 `sqlmap`）的载荷被Web应用防火墙（WAF）拦截时，用于生成自定义载荷以尝试绕过。

**[ 5. 专项逻辑测试 ]**
* `graphql_scanner`: (按需使用) **仅**在 `whatweb_scan` 或 `dirsearch_scan` 发现 `/graphql` 端点时使用。
* `business_logic_testing`: (高级) 用于测试价格篡改、权限绕过等无法被自动化工具扫描的业务逻辑漏洞。

"""

        try:
            result = await self._run_execution_loop(
                system_prompt=system_prompt,
                instruction=instruction,
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

    async def _run_execution_loop(self, system_prompt: str, instruction: str, max_rounds: int, phase_tools: List):
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
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": instruction}
        ]

        # 记录开始
        target_url = instruction.split("目标: ")[1].split("\n")[0] if "目标: " in instruction else ""
        log_phase_start(0, self.name, target_url)

        rounds_completed = 0
        # 简化版本：不做消息总结，直接使用固定窗口
        while True:
            # 记录LLM请求
            log_llm_request(messages, "MiniMaxAI/MiniMax-M2", 0, max_rounds)

            # 第一次调用：发送请求到模型
            response = await client.chat.completions.create(
                model="MiniMaxAI/MiniMax-M2",
                messages=messages,
                tools=transformed_tools,
                tool_choice="auto",
                temperature=0.7
            )

            # 记录使用情况
            usage_tracker = get_current_usage_tracker()
            if usage_tracker and hasattr(response, 'usage'):
                usage_tracker.log_agent_usage(response.usage, get_current_target_url())

            # 获取助手回复
            response_message = response.choices[0].message
            tool_calls = response_message.tool_calls

            # 记录LLM响应
            log_llm_response(
                response_message.content if response_message.content else "",
                0,
                len(tool_calls) if tool_calls else 0
            )

            # 检查模型是否决定调用函数
            if not tool_calls:
                # 没有函数调用，返回最终答案
                return response_message.content

            # 将助手的回复（包含 tool_calls）添加到消息历史中
            assistant_message = {
                "role": "assistant",
                "content": response_message.content,
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

                # 检查工具结果中是否包含flag
                import re
                # 严格的flag格式匹配（UUID格式：8-4-4-4-12位十六进制）
                flag_patterns = [
                    r'flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}',
                    r'FLAG\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}'
                ]
                for pattern in flag_patterns:
                    flag_match = re.search(pattern, str(result), re.IGNORECASE)
                    if flag_match:
                        flag = flag_match.group(0)
                        logger.info(f"[单Agent: {self.name}] 在工具结果中发现flag: {flag}")
                        # 将函数执行结果添加回消息历史
                        tool_message = {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": tool_call.function.name,
                            "content": str(result)
                        }
                        messages.append(tool_message)
                        return str(result)

                # 将函数执行结果添加回消息历史
                tool_message = {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "name": tool_call.function.name,
                    "content": str(result)
                }
                messages.append(tool_message)

            rounds_completed += 1

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
