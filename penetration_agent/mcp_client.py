import asyncio
import os
import json
import sys
from typing import Optional, List, Dict, Any
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()


class MCPClient:
    """MCP 客户端 - 通过 stdio 协议与 MCP 服务器通信"""

    def __init__(self):
        """初始化 MCP 客户端"""
        self.exit_stack = AsyncExitStack()
        self.session: Optional[ClientSession] = None
        self.available_tools = []

    async def connect_to_server(self, server_script_path: str):
        """连接到 MCP 服务器并获取工具列表"""
        print(f"[客户端] 正在启动并连接到 MCP 服务器: {server_script_path}...")

        if not server_script_path.endswith('.py'):
            raise ValueError("服务器脚本必须是 .py 文件")

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[server_script_path],
            env=None
        )

        stdio_transport = await self.exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        self.stdio, self.write = stdio_transport

        self.session = await self.exit_stack.enter_async_context(
            ClientSession(self.stdio, self.write)
        )
        await self.session.initialize()

        response = await self.session.list_tools()

        self.available_tools = [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema
                }
            }
            for tool in response.tools
        ]

        print(f"\n[客户端] ✅ 成功连接到服务器")
        print(f"[客户端] 获取到 {len(self.available_tools)} 个工具:")
        for tool in self.available_tools:
            print(f"  - {tool['function']['name']}: {tool['function']['description'][:60]}...")

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """调用指定的 MCP 工具"""
        if not self.session:
            return f"错误：未连接到 MCP 服务器"

        try:
            print(f"\n[客户端] 🔧 正在调用工具: {tool_name}({arguments})")
            result = await self.session.call_tool(tool_name, arguments)

            if result.content:
                tool_result = result.content[0].text
                print(f"[客户端] ✅ 工具执行完成")
                return tool_result
            else:
                return f"工具 {tool_name} 执行完成，但无返回内容"

        except Exception as e:
            error_msg = f"调用工具 {tool_name} 失败: {str(e)}"
            print(f"[客户端] ❌ {error_msg}")
            return error_msg

    async def list_tools(self) -> List[Dict[str, Any]]:
        """获取可用工具列表"""
        return self.available_tools

    async def cleanup(self):
        """清理资源"""
        print("\n[客户端] 正在关闭连接...")
        await self.exit_stack.aclose()
        print("[客户端] 已退出。")


# 全局客户端实例
_mcp_client = None


async def get_mcp_client(server_script: str = "mcp_server.py") -> MCPClient:
    """获取或创建 MCP 客户端实例"""
    global _mcp_client

    if _mcp_client is None:
        _mcp_client = MCPClient()
        await _mcp_client.connect_to_server(server_script)

    return _mcp_client


async def call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    """
    便捷函数：调用 MCP 工具

    Args:
        tool_name: 工具名称
        arguments: 工具参数

    Returns:
        工具执行结果
    """
    client = await get_mcp_client()
    return await client.call_tool(tool_name, arguments)


async def list_mcp_tools() -> List[Dict[str, Any]]:
    """
    获取所有可用的 MCP 工具列表

    Returns:
        工具列表
    """
    client = await get_mcp_client()
    return await client.list_tools()


async def cleanup_mcp_client():
    """清理 MCP 客户端资源"""
    global _mcp_client
    if _mcp_client:
        await _mcp_client.cleanup()
        _mcp_client = None