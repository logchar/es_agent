# coding:utf-8
"""
MCP 服务器：定义所有可用的工具函数
使用 FastMCP 框架，按五阶段渗透测试流程组织：侦察 -> 自动化扫描 -> 认证与会话 -> 高级模糊测试 -> 特定服务与逻辑
"""
import os
import logging
import asyncio
import time
import json
import re
from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
from fastmcp import FastMCP
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置日志
from logging_config import get_logger, log_tool_call, log_tool_result
logger = get_logger("mcp")

# 常量定义
DEFAULT_REQUEST_TIMEOUT = 30
MAX_RETRIES = 3

# 创建 MCP 服务器实例
mcp = FastMCP("hexstrike-ctf-tools")


def parse_katana_result(json_content: Dict[str, Any]) -> tuple[List[str], List[Dict[str, Any]]]:
    """
    解析katana结果，提取endpoints和forms信息

    Args:
        json_content: 从结果文件中读取的JSON对象

    Returns:
        tuple: (endpoints列表, forms列表)
    """
    endpoints = []
    forms = []

    # 从stdout字段中提取每行的JSON对象
    if 'stdout' in json_content and isinstance(json_content['stdout'], str):
        stdout_lines = json_content['stdout'].strip().split('\n')

        for line in stdout_lines:
            line = line.strip()
            if not line:
                continue

            try:
                inner_data = json.loads(line)

                # 提取endpoint信息
                if 'request' in inner_data and 'endpoint' in inner_data['request']:
                    endpoint = inner_data['request']['endpoint']
                    if endpoint and endpoint not in endpoints:
                        endpoints.append(endpoint)

                # 提取forms信息 (可能在response中)
                if 'forms' in inner_data:
                    for form in inner_data['forms']:
                        # 检查是否已存在相同的form
                        form_exists = False
                        for existing_form in forms:
                            if (existing_form.get('method') == form.get('method') and
                                existing_form.get('action') == form.get('action') and
                                existing_form.get('parameters') == form.get('parameters')):
                                form_exists = True
                                break

                        if not form_exists:
                            forms.append(form)
                elif 'response' in inner_data and 'forms' in inner_data['response']:
                    for form in inner_data['response']['forms']:
                        # 检查是否已存在相同的form
                        form_exists = False
                        for existing_form in forms:
                            if (existing_form.get('method') == form.get('method') and
                                existing_form.get('action') == form.get('action') and
                                existing_form.get('parameters') == form.get('parameters')):
                                form_exists = True
                                break

                        if not form_exists:
                            forms.append(form)

            except json.JSONDecodeError:
                # 忽略无法解析的行
                continue

    return endpoints, forms


def parse_ssti_result(api_result: Dict[str, Any]) -> Dict[str, Any]:
    """解析HexStrike后端返回的SSTI检测结果"""
    
    # 基础结果结构
    result = {
        "vulnerable": api_result.get("vulnerable", False),
        "engine": api_result.get("engine", "unknown"),
        "injection_point": api_result.get("injection_point", ""),
        "technique": api_result.get("technique", ""),
        "capabilities": api_result.get("capabilities", {}),
        "output": api_result.get("output", ""),
        "risk_level": "low"
    }
    
    # 根据漏洞信息计算风险等级
    if result["vulnerable"]:
        capabilities = result["capabilities"]
        if capabilities.get("command_execution") or capabilities.get("reverse_shell"):
            result["risk_level"] = "critical"
        elif capabilities.get("file_read") or capabilities.get("file_write"):
            result["risk_level"] = "high"
        elif capabilities.get("code_evaluation"):
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
    
    # 生成修复建议
    recommendations = []
    if result["vulnerable"]:
        recommendations.extend([
            "立即修复SSTI漏洞，避免远程代码执行",
            "对用户输入进行严格的验证和过滤",
            "使用安全的模板渲染方法，避免直接拼接用户输入",
            f"针对{result['engine']}引擎实施特定的安全配置"
        ])
        
        if result["risk_level"] in ["critical", "high"]:
            recommendations.append("⚠️ 高危漏洞！建议立即隔离系统并进行紧急修复")
    else:
        recommendations.extend([
            "继续保持安全编码实践",
            "定期进行安全测试",
            "确保所有用户输入都经过适当验证"
        ])
    
    result["recommendations"] = recommendations
    
    return result


# ========================================
# 通用工具（所有阶段可用）
# ========================================

@mcp.tool()
async def run_python(python_code: str, timeout: int = 120) -> str:
    """
    Execute Python code directly and return stdout/stderr/exit code.

    Args:
        python_code: Python code to execute (e.g., "print('Hello World')").
        timeout: Max seconds to wait before timing out the code execution.

    Returns:
        A string containing exit code, stdout, and stderr.
    """
    start_time = time.time()
    python_output = None
    error_msg = None
    success = False
    try:
        # 记录工具调用
        log_tool_call("run_python", {"python_code": python_code[:200], "timeout": timeout})

        import subprocess
        import tempfile
        import uuid

        # Create a temporary Python file
        script_name = f"temp_script_{uuid.uuid4().hex[:8]}.py"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, prefix=script_name) as f:
            f.write(python_code)
            script_path = f.name

        try:
            # Execute the Python script directly
            result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            stdout_raw = result.stdout if result.stdout else ""
            stderr_raw = result.stderr if result.stderr else ""
            exit_code = result.returncode if result.returncode is not None else "unknown"

            output = f"Exit code: {exit_code}\n\nSTDOUT\n{stdout_raw}\n\nSTDERR\n{stderr_raw}"

            if len(output) > 30000:
                output = (
                    output[:30000]
                    + "\n...[OUTPUT TRUNCATED - EXCEEDED 30000 CHARACTERS]"
                )

            python_output = output
            success = True
            return output
        finally:
            # Clean up the temporary file
            try:
                import os
                if os.path.exists(script_path):
                    os.unlink(script_path)
            except Exception:
                pass
    except subprocess.TimeoutExpired:
        error_msg = f"Python code execution timed out after {timeout} seconds"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Failed to run Python code: {e}"
        logger.error(error_msg, exc_info=True)
        return error_msg
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        result = python_output if success else error_msg
        if result is None:
            result = 'No result' if success else 'Execution failed'
        log_tool_result("run_python", result, duration, success)


@mcp.tool()
async def run_command(command: str, timeout: int = 120) -> str:
    """
    Execute a shell command directly and return stdout/stderr/exit code.

    Args:
        command: Shell command to execute (e.g., "ls -la").
        timeout: Max seconds to wait before timing out the command.

    Returns:
        A string containing exit code, stdout, and stderr.
    """
    start_time = time.time()
    command_output = None
    error_msg = None
    success = False
    try:
        # 记录工具调用
        log_tool_call("run_command", {"command": command, "timeout": timeout})

        import subprocess

        # Execute the command directly using subprocess
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        stdout_raw = result.stdout if result.stdout else ""
        stderr_raw = result.stderr if result.stderr else ""
        exit_code = result.returncode if result.returncode is not None else "unknown"

        output = f"Exit code: {exit_code}\n\nSTDOUT\n{stdout_raw}\n\nSTDERR\n{stderr_raw}"

        command_output = output
        success = True
        return output
    except subprocess.TimeoutExpired:
        error_msg = f"Command execution timed out after {timeout} seconds"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Failed to run command: {e}"
        logger.error(error_msg, exc_info=True)
        return error_msg
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        result = command_output if success else error_msg
        if result is None:
            result = 'No output' if success else 'Execution failed'
        log_tool_result("run_command", result, duration, success)


@mcp.tool()
async def whatweb_scan(url: str, aggression_level: int = 3,
                       additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段1: 侦察] WhatWeb Web应用识别工具

    识别网站使用的技术栈、CMS、服务器、框架等信息 - 对应 "信息泄露" 类漏洞。
    类似于浏览器开发者工具的"查看页面信息"功能。

    Args:
        url: 目标URL
        aggression_level: агрессивность扫描级别 (1-4)，默认为 3 (激进模式)
                         1: 轻量级 (快速)
                         2: 标准 (默认)
                         3: 激进 (更准确但更慢)
                         4: 暴力 (最准确但最慢)
        additional_args: 额外的WhatWeb参数

    Returns:
        Web应用识别结果，包含技术栈信息
    """
    start_time = time.time()
    scan_result = None
    error_msg = None
    success = False
    try:
        # 记录工具调用
        log_tool_call("whatweb_scan", {
            "url": url,
            "aggression_level": aggression_level,
            "additional_args": additional_args
        }, url)

        import subprocess
        import re

        # 构建 whatweb 命令，参考用户提供的格式：whatweb -v -a 3
        cmd_parts = ["whatweb", "-v"]  # verbose 模式
        cmd_parts.append(f"-a {aggression_level}")

        if additional_args:
            cmd_parts.append(additional_args)

        cmd_parts.append(url)
        command = " ".join(cmd_parts)

        logger.info(f"[阶段1: 侦察] 启动WhatWeb识别: {url}")

        # 执行命令
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )

        stdout = result.stdout if result.stdout else ""
        stderr = result.stderr if result.stderr else ""
        exit_code = result.returncode if result.returncode is not None else -1

        # 清理 ANSI 颜色码
        ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKF]')
        stdout_clean = ansi_escape.sub('', stdout)

        # 解析结果
        if exit_code == 0 and stdout_clean:
            logger.info(f"[阶段1: 侦察] WhatWeb识别完成: {url}")

            # 解析 WhatWeb 输出
            parsed_result = {
                "success": True,
                "url": url,
                "exit_code": exit_code,
                "summary": {},
                "plugins": []
            }

            # 提取基本信息
            if "Status" in stdout_clean:
                status_match = re.search(r'Status\s+:\s+(\d+)\s+(\w+)', stdout_clean)
                if status_match:
                    parsed_result["summary"]["status_code"] = status_match.group(1)
                    parsed_result["summary"]["status_text"] = status_match.group(2)

            if "Title" in stdout_clean:
                title_match = re.search(r'Title\s+:\s+(.+)', stdout_clean)
                if title_match:
                    parsed_result["summary"]["title"] = title_match.group(1).strip()

            if "IP" in stdout_clean:
                ip_match = re.search(r'IP\s+:\s+(.+)', stdout_clean)
                if ip_match:
                    parsed_result["summary"]["ip"] = ip_match.group(1).strip()

            if "Country" in stdout_clean:
                country_match = re.search(r'Country\s+:\s+(.+)', stdout_clean)
                if country_match:
                    parsed_result["summary"]["country"] = country_match.group(1).strip()

            # 解析检测到的插件
            lines = stdout_clean.split('\n')
            current_plugin = None
            plugins = []

            for line in lines:
                line = line.strip()

                if line.startswith('[') and ']' in line:
                    if current_plugin:
                        plugins.append(current_plugin)

                    plugin_name = line[1:line.find(']')].strip()
                    current_plugin = {
                        "name": plugin_name,
                        "version": None,
                        "website": None
                    }
                elif current_plugin:
                    if line.startswith('Version') and ':' in line:
                        current_plugin["version"] = line.split(':', 1)[1].strip()
                    elif line.startswith('Website') and ':' in line:
                        current_plugin["website"] = line.split(':', 1)[1].strip()

            if current_plugin:
                plugins.append(current_plugin)

            parsed_result["plugins"] = plugins
            parsed_result["plugin_count"] = len(plugins)

            # 提取 HTTP 头信息
            if "HTTP Headers:" in stdout_clean or "HTTP/" in stdout_clean:
                headers_section = stdout_clean[stdout_clean.find("HTTP/"):] if "HTTP/" in stdout_clean else ""
                if "HTTP Headers:" in headers_section:
                    headers_start = headers_section.find("HTTP Headers:")
                    headers_text = headers_section[headers_start:].split("\n\n")[0]

                    headers = {}
                    for header_line in headers_text.split("\n")[1:]:  # 跳过 "HTTP Headers:" 行
                        if ":" in header_line:
                            key, value = header_line.split(":", 1)
                            headers[key.strip()] = value.strip()

                    parsed_result["summary"]["http_headers"] = headers

            scan_result = parsed_result
            success = True
            return parsed_result
        else:
            error_msg = f"WhatWeb识别失败: exit_code={exit_code}"
            logger.error(f"[阶段1: 侦察] {error_msg}")
            return {
                "success": False,
                "url": url,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "error": "WhatWeb command failed or returned no output"
            }
    except subprocess.TimeoutExpired:
        error_msg = f"WhatWeb scan timed out for {url}"
        logger.error(error_msg)
        return {"success": False, "url": url, "error": error_msg}
    except Exception as e:
        error_msg = f"Failed to run WhatWeb: {e}"
        logger.error(error_msg, exc_info=True)
        return {"success": False, "url": url, "error": error_msg}
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        result = scan_result if success else error_msg
        if result is None:
            result = 'No result' if success else 'Scan failed'
        log_tool_result("whatweb_scan", result, duration, success)


# ========================================
# HexStrike 客户端
# ========================================

class HexStrikeClient:
    """增强型HexStrike AI API服务器客户端"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        初始化HexStrike AI客户端

        Args:
            server_url: HexStrike AI API服务器URL
            timeout: 请求超时时间（秒）
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        import requests
        self.session = requests.Session()

        # 尝试连接服务器，支持重试
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"尝试连接HexStrike AI API: {server_url} (第{i+1}/{MAX_RETRIES}次)")
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"成功连接到HexStrike AI API服务器: {server_url}")
                    logger.info(f"服务器健康状态: {health_check.get('status', 'unknown')}")
                    logger.info(f"服务器版本: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"拒绝连接到 {server_url}。请确保HexStrike AI服务器正在运行。")
                    time.sleep(2)
                except Exception as e:
                    logger.warning(f"连接测试失败: {str(e)}")
                    time.sleep(2)
            except Exception as e:
                logger.warning(f"第{i+1}次连接失败: {str(e)}")
                time.sleep(2)

        if not connected:
            error_msg = f"经过 {MAX_RETRIES} 次尝试后，仍无法连接到HexStrike AI API服务器 {server_url}"
            logger.error(error_msg)

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        执行GET请求，支持可选的查询参数

        Args:
            endpoint: API端点路径（无前导斜杠）
            params: 可选的查询参数

        Returns:
            响应数据字典
        """
        import requests

        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} 参数: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"请求失败: {str(e)}")
            return {"error": f"请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"意外错误: {str(e)}")
            return {"error": f"意外错误: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行POST请求，发送JSON数据

        Args:
            endpoint: API端点路径（无前导斜杠）
            json_data: 要发送的JSON数据

        Returns:
            响应数据字典
        """
        import requests

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"POST {url} 数据: {json_data}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"请求失败: {str(e)}")
            return {"error": f"请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"意外错误: {str(e)}")
            return {"error": f"意外错误: {str(e)}", "success": False}

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        在HexStrike服务器上执行通用命令

        Args:
            command: 要执行的命令
            use_cache: 是否为该命令使用缓存

        Returns:
            命令执行结果
        """
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def check_health(self) -> Dict[str, Any]:
        """
        检查HexStrike AI API服务器健康状态

        Returns:
            健康状态信息
        """
        return self.safe_get("health")


# 全局客户端实例
_hexstrike_client = None

def get_hexstrike_client() -> Optional[HexStrikeClient]:
    """获取或创建 HexStrike 客户端实例"""
    global _hexstrike_client
    if _hexstrike_client is None:
        hexstrike_url = os.getenv("HEXSTRIKE_SERVER_URL")
        if hexstrike_url:
            _hexstrike_client = HexStrikeClient(hexstrike_url)
    return _hexstrike_client


# ========================================
# 阶段1：侦察工具
# ========================================

@mcp.tool()
async def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True,
                     form_extraction: bool = True, output_format: str = "json",
                     additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段1: 侦察] Katana下一代爬虫和蜘蛛工具

    执行自动化的网站爬取，发现所有可访问的页面、端点、JavaScript文件和表单。
    这是后续所有测试的基础 - 对应 "信息泄露" 类漏洞。

    Args:
        url: 目标URL
        depth: 爬取深度
        js_crawl: 启用JavaScript爬取
        form_extraction: 启用表单提取
        output_format: 输出格式 (json, txt)
        additional_args: 额外的Katana参数

    Returns:
        高级网站爬取结果，包含端点和表单 (不含 raw_result)
    """
    start_time = time.time()
    katana_result = None
    error_msg = None
    success = False
    try:
        # 记录工具调用
        log_tool_call("katana_crawl", {
            "url": url,
            "depth": depth,
            "js_crawl": js_crawl,
            "form_extraction": form_extraction,
            "output_format": output_format,
            "additional_args": additional_args
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "url": url,
            "depth": depth,
            "js_crawl": js_crawl,
            "form_extraction": form_extraction,
            "output_format": output_format, # 确保服务器端确实在生成 json
            "additional_args": additional_args
        }
        logger.info(f"[阶段1: 侦察] 启动Katana爬取: {url}")
        result = client.safe_post("api/tools/katana", data)

        # 检查 API 调用是否成功
        if result.get("success"):
            logger.info(f"[阶段1: 侦察] Katana 任务完成，正在解析结果...")

            try:
                # 解析stdout并提取endpoints和forms
                endpoints, forms = parse_katana_result(result)
                logger.info(f"[阶段1: 侦察] Katana爬取完成: {url}")
                logger.info(f"[阶段1: 侦察] 发现 {len(endpoints)} 个端点, {len(forms)} 个表单")

                # 将解析结果添加到result中
                result["endpoints"] = endpoints
                result["forms"] = forms

                # 清理不需要的字段
                result.pop("stdout", None)
                result.pop("stderr", None)

                katana_result = result
                success = True
                return result

            except Exception as e:
                logger.error(f"[阶段1: 侦察] 解析结果时发生错误: {e}")
                return {"error": f"Failed to parse result: {e}", "success": False}
        else:
            # API 调用本身失败了
            logger.error(f"[阶段1: 侦察] Katana爬取失败: {url}，服务器返回: {result.get('error')}")
            return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        result = katana_result if success else error_msg
        if result is None:
            result = 'No result' if success else 'Crawl failed'
        log_tool_result("katana_crawl", result, duration, success)


@mcp.tool()
async def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json",
                       wordlist: str = "/usr/share/wordlists/dirsearch/common.txt",
                       threads: int = 30, recursive: bool = False,
                       additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段1: 侦察] Dirsearch高级目录和文件发现工具

    发现隐藏的目录和文件（如 .git, .env, admin 页面）- 对应 "信息泄露" 类漏洞。

    Args:
        url: 目标URL
        extensions: 要搜索的文件扩展名
        wordlist: 要使用的字典文件
        threads: 线程数
        recursive: 启用递归扫描
        additional_args: 额外的Dirsearch参数

    Returns:
        高级目录发现结果，包含原始 stderr 和解析后的 "findings" 列表
    """
    start_time = time.time()
    dirsearch_result = None
    error_msg = None
    success = False
    try:
        # 记录工具调用
        log_tool_call("dirsearch_scan", {
            "url": url,
            "extensions": extensions,
            "wordlist": wordlist,
            "threads": threads,
            "recursive": recursive,
            "additional_args": additional_args
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "url": url,
            "extensions": extensions,
            "wordlist": wordlist,
            "threads": threads,
            "recursive": recursive,
            "additional_args": additional_args
        }
        logger.info(f"[阶段1: 侦察] 启动Dirsearch扫描: {url}")

        # 1. 调用 hexstrike API
        result = client.safe_post("api/tools/dirsearch", data)

        # 2. 检查调用是否成功
        if not result.get("success"):
            logger.error(f"[阶段1: 侦察] Dirsearch扫描失败 (hexstrike API error): {url}")
            # 即使失败，也返回原始的 result，其中包含错误信息
            return result

        # 3. (*** 新增逻辑 ***)
        #    如果调用成功，则解析 hexstrike 返回的 stdout
        logger.info(f"[阶段1: 侦察] Dirsearch扫描完成，正在解析结果: {url}")

        parsed_findings = []
        stdout = result.get("stdout") # 从 hexstrike 结果中获取 stdout

        if stdout:
            # 使用与 test_dirsearch.py 中相同的正则表达式
            pattern = re.compile(r"\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+([\w\.]+)\s+-\s+(.+)")

            stdout_lines = stdout.splitlines()

            for line in stdout_lines:
                match = pattern.search(line)
                if match:
                    # 匹配成功，提取捕获组
                    status = match.group(1)
                    size = match.group(2)
                    path_info = match.group(3).strip()

                    finding = {
                        "status": status,
                        "size": size,
                        "path": path_info
                    }
                    parsed_findings.append(finding)

            # 4. (*** 修改日志 ***)
            #    更新日志以反映解析到的发现
            logger.info(f"[阶段1: 侦察] 解析完成，发现 {len(parsed_findings)} 个有效路径。")

        else:
            logger.warning(f"[阶段1: 侦察] Dirsearch 扫描的 stdout 为空: {url}")

        # 5. (*** 关键修复 ***)
        # 1. 添加解析后的 "findings" 列表
        result["findings"] = parsed_findings
        dirsearch_result = result
        success = True

        # 2. (新增) 从字典中删除原始的、冗长的 stdout
        if "stdout" in result:
            del result["stdout"]

        # 6. 返回更新后的 "result" 字典
        #    它现在包含: "success", "stderr", 以及 "findings" (没有 stdout)
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        result = dirsearch_result if success else error_msg
        if result is None:
            result = 'No result' if success else 'Scan failed'
        log_tool_result("dirsearch_scan", result, duration, success)

@mcp.tool()
async def arjun_parameter_discovery(url: str, method: str = "GET", wordlist: str = "",
                              delay: int = 0, threads: int = 10, stable: bool = False,
                              additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段1: 侦察] Arjun HTTP参数发现工具

    在katana_crawl发现的端点上自动查找隐藏的HTTP参数。
    这是测试注入类漏洞的关键 - 对应 "IDOR", "XSS" 等漏洞。

    Args:
        url: 目标URL
        method: 要使用的HTTP方法
        wordlist: 自定义字典文件
        delay: 请求之间的延迟
        threads: 线程数
        stable: 使用稳定模式
        additional_args: 额外的Arjun参数

    Returns:
        HTTP参数发现结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("arjun_parameter_discovery", {
            "url": url,
            "method": method,
            "wordlist": wordlist,
            "delay": delay,
            "threads": threads,
            "stable": stable,
            "additional_args": additional_args
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "url": url,
            "method": method,
            "wordlist": wordlist,
            "delay": delay,
            "threads": threads,
            "stable": stable,
            "additional_args": additional_args
        }
        logger.info(f"[阶段1: 侦察] 启动Arjun参数发现: {url}")
        result = client.safe_post("api/tools/arjun", data)
        if result.get("success"):
            logger.info(f"[阶段1: 侦察] Arjun参数发现完成: {url}")
            ansi_pattern = re.compile(r'\x1b\[[0-9;]*m')
            # 筛除颜色
            for key in list(result.keys()):
                value = result[key]
                cleaned_value = value

                if isinstance(value, str):
                    cleaned_value = ansi_pattern.sub('', value)
                    result[key] = cleaned_value

                cleaned_key = key
                if isinstance(key, str):
                    cleaned_key = ansi_pattern.sub('', key)

                if key != cleaned_key:
                    result[cleaned_key] = cleaned_value
                    del result[key]

            prefixes_to_keep = ('[-]', '[✓]', '[+]')
            filtered_lines = []
            cleaned_value = result['output']
            for line in cleaned_value.splitlines():
                if line.strip().startswith(prefixes_to_keep):
                    filtered_lines.append(line)

            result['output'] = "\n".join(filtered_lines)
            result['stdout'] = "\n".join(filtered_lines)
            logger.info(f"[阶段1: 侦察] 发现 {len(filtered_lines)} 个参数")
            success = True
        else:
            logger.error(f"[阶段1: 侦察] Arjun参数发现失败: {url}")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("arjun_parameter_discovery", tool_result, duration, success)


# ========================================
# 阶段2：自动化扫描工具
# ========================================

@mcp.tool()
async def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段2: 自动化扫描] SQLMap SQL注入测试工具

    自动检测和利用SQL注入漏洞的最佳工具 - 对应 "SQLI / BLIND_SQLI" 漏洞。

    Args:
        url: 目标URL
        data: POST数据用于测试
        additional_args: 额外的SQLMap参数

    Returns:
        SQL注入测试结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("sqlmap_scan", {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        def _prepare_additional_args(args: str) -> str:
            """确保输出更直接并避免交互：默认添加 --forms --crawl=2 --batch --disable-coloring。
            若用户已提供参数，仅补齐 --batch / --disable-coloring。"""
            args = (args or "").strip()
            if not args:
                return "--batch --disable-coloring -v 0"
            needed = ["--batch", "--disable-coloring", "-v 0"]
            for flag in needed:
                if flag not in args:
                    args += f" {flag}"
            return args.strip()

        data_payload = {
            "url": url,
            "data": data,
            "additional_args": _prepare_additional_args(additional_args)
        }
        logger.info(f"[阶段2: 自动化扫描] 启动SQLMap扫描: {url}")

        def _trim_stdout(stdout: str) -> str:
            """裁剪 sqlmap 输出，去掉 '[*] starting' 之前的内容"""
            if not stdout:
                return stdout
            marker = "[*] starting"
            idx = stdout.find(marker)
            if idx != -1:
                return stdout[idx:]
            return stdout

        result = client.safe_post("api/tools/sqlmap", data_payload)
        if "stdout" in result:
            trimmed = _trim_stdout(result.get("stdout", "") or "")
            result["stdout"] = trimmed
        if result.get("success"):
            logger.info(f"[阶段2: 自动化扫描] SQLMap扫描完成: {url}")
            vulnerabilities = result.get("vulnerabilities", [])
            if vulnerabilities:
                logger.warning(f"[阶段2: 自动化扫描] 发现 {len(vulnerabilities)} 个SQL注入漏洞!")
            success = True
        else:
            logger.error(f"[阶段2: 自动化扫描] SQLMap扫描失败: {url}")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("sqlmap_scan", tool_result, duration, success)

def clean_dalfox_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    清洗 Dalfox 扫描结果，提取有效信息

    Args:
        result: 原始的 Dalfox 扫描结果

    Returns:
        清洗后的结果，包含关键信息和解析后的数据
    """
    cleaned = {
        # 基本执行信息
        "success": result.get("success", False),
        "execution_time": result.get("execution_time", 0),
        "return_code": result.get("return_code", -1),
        "timed_out": result.get("timed_out", False),
        "timestamp": result.get("timestamp", ""),

        # 解析后的扫描信息
        "findings": result.get("findings", []),
        "statistics": {}
    }

    # 解析 stderr 中的有用信息
    stderr = result.get("stderr", "")
    if stderr:
        import re

        # 去除 ANSI 颜色码
        ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKF]')
        stderr_clean = ansi_escape.sub('', stderr)

        # 提取持续时间和问题数量
        duration_match = re.search(r'\[duration: ([^\]]+)\]\[issues: (\d+)\]', stderr_clean)
        if duration_match:
            cleaned["statistics"]["issues_count"] = int(duration_match.group(2))

    # 添加统计信息
    cleaned["statistics"].update({
        "total_findings": len(cleaned["findings"]),
        "has_findings": len(cleaned["findings"]) > 0
    })

    return cleaned


@mcp.tool()
async def dalfox_xss_scan(url: str, pipe_mode: bool = False, blind: bool = False,
                    mining_dom: bool = True, mining_dict: bool = True,
                    custom_payload: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段2: 自动化扫描] Dalfox高级XSS漏洞扫描工具

    专门为XSS设计的高级扫描器，优于通用模糊测试工具 - 对应 "XSS" 漏洞。

    Args:
        url: 目标URL
        pipe_mode: 使用管道模式输入
        blind: 启用盲XSS测试
        mining_dom: 启用DOM挖掘
        mining_dict: 启用字典挖掘
        custom_payload: 自定义XSS载荷
        additional_args: 额外的Dalfox参数

    Returns:
        高级XSS漏洞扫描结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("dalfox_xss_scan", {
            "url": url,
            "pipe_mode": pipe_mode,
            "blind": blind,
            "mining_dom": mining_dom,
            "mining_dict": mining_dict,
            "custom_payload": custom_payload,
            "additional_args": additional_args
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "url": url,
            "pipe_mode": pipe_mode,
            "blind": blind,
            "mining_dom": mining_dom,
            "mining_dict": mining_dict,
            "custom_payload": custom_payload,
            "additional_args": additional_args
        }
        logger.info(f"[阶段2: 自动化扫描] 启动Dalfox XSS扫描: {url if url else '管道模式'}")
        result = client.safe_post("api/tools/dalfox", data)
        if result.get("success"):
            logger.info(f"[阶段2: 自动化扫描] Dalfox XSS扫描完成")
            result=clean_dalfox_result(result)

            return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("dalfox_xss_scan", tool_result, duration, success)


@mcp.tool()
async def dotdotpwn_scan(target: str, module: str = "http", additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段2: 自动化扫描] DotDotPwn目录遍历测试工具

    专门用于模糊测试路径遍历和LFI漏洞 - 对应 "LFI / PATH_TRAVERSAL" 漏洞。

    Args:
        target: 目标主机名或IP
        module: 要使用的模块 (http, ftp, tftp等)
        additional_args: 额外的DotDotPwn参数

    Returns:
        目录遍历测试结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("dotdotpwn_scan", {
            "target": target,
            "module": module,
            "additional_args": additional_args
        }, target)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "target": target,
            "module": module,
            "additional_args": additional_args
        }
        logger.info(f"[阶段2: 自动化扫描] 启动DotDotPwn扫描: {target}")
        result = client.safe_post("api/tools/dotdotpwn", data)
        if result.get("success"):
            logger.info(f"[阶段2: 自动化扫描] DotDotPwn扫描完成: {target}")
            traversals = result.get("directory_traversals", [])
            if traversals:
                logger.warning(f"[阶段2: 自动化扫描] 发现 {len(traversals)} 个路径遍历漏洞!")
            success = True
        else:
            logger.error(f"[阶段2: 自动化扫描] DotDotPwn扫描失败: {target}")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("dotdotpwn_scan", tool_result, duration, success)


@mcp.tool()
async def nuclei_scan(target: str, severity: str = "", tags: str = "",
                template: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段2: 自动化扫描] Nuclei漏洞扫描器

    快速扫描已知CVE和常见错误配置 - 对应 "CVE" 类漏洞。
    （前提是hexstrike_server有本地模板库）

    Args:
        target: 目标URL或IP
        severity: 按严重性过滤 (critical,high,medium,low,info)
        tags: 按标签过滤 (如 cve,rce,lfi)
        template: 自定义模板路径
        additional_args: 额外的Nuclei参数

    Returns:
        扫描结果，包含发现的漏洞和遥测数据
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("nuclei_scan", {
            "target": target,
            "severity": severity,
            "tags": tags,
            "template": template,
            "additional_args": additional_args
        }, target)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "target": target,
            "severity": severity,
            "tags": tags,
            "template": template,
            "additional_args": additional_args
        }
        logger.info(f"[阶段2: 自动化扫描] 启动Nuclei漏洞扫描: {target}")
        result = client.safe_post("api/tools/nuclei", data)
        if result.get("success"):
            logger.info(f"[阶段2: 自动化扫描] Nuclei扫描完成: {target}")

            # 增强的漏洞报告
            if result.get("stdout") and "CRITICAL" in result["stdout"]:
                logger.warning(f"[阶段2: 自动化扫描] 检测到CRITICAL级别漏洞!")
            elif result.get("stdout") and "HIGH" in result["stdout"]:
                logger.warning(f"[阶段2: 自动化扫描] 发现HIGH级别漏洞!")
            success = True
        else:
            logger.error(f"[阶段2: 自动化扫描] Nuclei扫描失败: {target}")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("nuclei_scan", tool_result, duration, success)


# ========================================
# 阶段3：认证与会话工具
# ========================================

@mcp.tool()
async def hydra_attack(target: str, service: str, username: str = "",
                 username_file: str = "", password: str = "",
                 password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    [阶段3: 认证与会话] Hydra密码暴力破解工具

    经典的登录暴力破解工具，适用于Web表单和多种网络服务。
    - 对应 "DEFAULT_CREDENTIALS / BRUTE_FORCE" 漏洞

    Args:
        target: 目标IP或主机名
        service: 要攻击的服务 (ssh, ftp, http等)
        username: 要测试的单个用户名
        username_file: 包含用户名的文件
        password: 要测试的单个密码
        password_file: 包含密码的文件
        additional_args: 额外的Hydra参数

    Returns:
        暴力破解攻击结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("hydra_attack", {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }, target)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        logger.info(f"[阶段3: 认证与会话] 启动Hydra攻击: {target}:{service}")
        result = client.safe_post("api/tools/hydra", data)
        if result.get("success"):
            logger.info(f"[阶段3: 认证与会话] Hydra攻击完成: {target}")
            credentials = result.get("found_credentials", [])
            if credentials:
                logger.warning(f"[阶段3: 认证与会话] 发现有效凭据: {credentials}")
            success = True
        else:
            logger.error(f"[阶段3: 认证与会话] Hydra攻击失败: {target}")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("hydra_attack", tool_result, duration, success)


@mcp.tool()
async def jwt_analyzer(jwt_token: str, target_url: str = "") -> Dict[str, Any]:
    """
    [阶段3: 认证与会话] JWT令牌分析器

    专门用于分析JWT令牌、检查弱密钥和"none"算法漏洞 - 对应 "JWT" 漏洞。

    Args:
        jwt_token: 要分析的JWT令牌
        target_url: 可选的测试令牌操作的目标URL

    Returns:
        JWT分析结果，包含漏洞评估和攻击向量
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("jwt_analyzer", {
            "jwt_token": jwt_token[:50] + "..." if len(jwt_token) > 50 else jwt_token,
            "target_url": target_url
        }, target_url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "jwt_token": jwt_token,
            "target_url": target_url
        }
        logger.info(f"[阶段3: 认证与会话] 启动JWT安全分析")
        result = client.safe_post("api/tools/jwt_analyzer", data)
        if result.get("success"):
            analysis = result.get("jwt_analysis_results", {})
            vuln_count = len(analysis.get("vulnerabilities", []))
            algorithm = analysis.get("token_info", {}).get("algorithm", "unknown")

            logger.info(f"[阶段3: 认证与会话] JWT分析完成: 发现 {vuln_count} 个漏洞")
            logger.info(f"[阶段3: 认证与会话] 令牌算法: {algorithm}")

            if vuln_count > 0:
                logger.warning(f"[阶段3: 认证与会话] 发现 {vuln_count} 个JWT漏洞!")
            success = True
        else:
            logger.error(f"[阶段3: 认证与会话] JWT分析失败")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("jwt_analyzer", tool_result, duration, success)


@mcp.tool()
async def idor_testing(base_url: str, identifier_param: str = "id",
                 start_range: int = 1, end_range: int = 100,
                 method: str = "GET", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    [阶段3: 认证与会话] IDOR (不安全的直接对象引用) 测试

    测试对识别出的ID（如 id=1, id=2）进行自动化数字枚举。
    - 对应 "IDOR" 漏洞

    Args:
        base_url: 基础URL (例如: https://example.com/profile)
        identifier_param: 标识符参数名 (默认: "id")
        start_range: 开始范围
        end_range: 结束范围
        method: HTTP方法
        headers: 额外的HTTP头

    Returns:
        IDOR测试结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("idor_testing", {
            "base_url": base_url,
            "identifier_param": identifier_param,
            "start_range": start_range,
            "end_range": end_range,
            "method": method,
            "headers": headers or {}
        }, base_url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "base_url": base_url,
            "identifier_param": identifier_param,
            "start_range": start_range,
            "end_range": end_range,
            "method": method,
            "headers": headers or {}
        }
        logger.info(f"[阶段3: 认证与会话] 启动IDOR测试: {base_url}")
        logger.info(f"[阶段3: 认证与会话] 测试范围: {start_range} - {end_range}，参数: {identifier_param}")

        # 使用http_intruder进行IDOR测试
        payload = {
            "action": "intruder",
            "url": base_url,
            "method": method,
            "location": "query",
            "params": [identifier_param],
            "payloads": list(range(start_range, end_range + 1)),
            "headers": headers or {},
            "max_requests": end_range - start_range + 1
        }

        result = client.safe_post("api/tools/http-framework", payload)
        if result.get("success"):
            logger.info(f"[阶段3: 认证与会话] IDOR测试完成")
            successful_requests = result.get("successful_requests", [])
            if successful_requests:
                logger.warning(f"[阶段3: 认证与会话] 发现 {len(successful_requests)} 个成功的IDOR请求")
            success = True
        else:
            logger.error(f"[阶段3: 认证与会话] IDOR测试失败")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("idor_testing", tool_result, duration, success)


@mcp.tool()
async def ssti_detection(
    url: str,
    parameter: str,
    engine: str = "auto",
    technique: str = "R",
    interactive: bool = False,
    os_shell: bool = False,
    eval_shell: bool = False,
    upload: Optional[str] = None,
    download: Optional[str] = None,
    additional_args: str = ""
) -> Dict[str, Any]:
    """
    [阶段2: 漏洞检测] SSTI（服务器端模板注入）检测与利用工具
    
    自动检测和利用服务器端模板注入漏洞，支持多种模板引擎和利用技术。
    
    Args:
        url: 目标URL
        parameter: 要测试的参数名
        engine: 模板引擎类型 (auto, jinja2, twig, smarty, etc.)
        technique: 检测技术 (R:渲染, E:错误, B:布尔盲注, T:时间盲注)
        interactive: 是否使用交互模式
        os_shell: 获取操作系统shell
        eval_shell: 获取代码评估shell
        upload: 文件上传 (本地路径 远程路径)
        download: 文件下载 (远程路径 本地路径)
        additional_args: 额外的SSTImap参数
        
    Returns:
        SSTI检测结果，包含漏洞信息和利用能力
    """
    start_time = time.time()
    ssti_result = None
    error_msg = None
    success = False
    
    try:
        # 记录工具调用
        log_tool_call("ssti_detection", {
            "url": url,
            "parameter": parameter,
            "engine": engine,
            "technique": technique,
            "interactive": interactive,
            "os_shell": os_shell,
            "eval_shell": eval_shell,
            "upload": upload,
            "download": download,
            "additional_args": additional_args
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL and HEXSTRIKE_API_KEY environment variables."
            return {"error": error_msg, "success": False}

        # 准备请求数据
        data = {
            "url": url,
            "parameter": parameter,
            "engine": engine,
            "technique": technique,
            "interactive": interactive,
            "os_shell": os_shell,
            "eval_shell": eval_shell,
            "upload": upload,
            "download": download,
            "additional_args": additional_args,
            "tool": "sstimap"  # 指定使用SSTImap工具
        }
        
        logger.info(f"[阶段2: 漏洞检测] 启动SSTI检测: {url}?{parameter}=*")
        
        # 调用HexStrike后端服务
        result = client.safe_post("api/tools/ssti", data)

        # 检查 API 调用是否成功
        if result.get("success"):
            logger.info(f"[阶段2: 漏洞检测] SSTI检测完成: {url}")
            
            try:
                # 解析后端返回的结果
                parsed_result = parse_ssti_result(result)
                
                ssti_result = {
                    "success": True,
                    "vulnerable": parsed_result.get("vulnerable", False),
                    "engine": parsed_result.get("engine", "unknown"),
                    "injection_point": parsed_result.get("injection_point", ""),
                    "technique": parsed_result.get("technique", ""),
                    "capabilities": parsed_result.get("capabilities", {}),
                    "output": parsed_result.get("output", ""),
                    "recommendations": parsed_result.get("recommendations", []),
                    "risk_level": parsed_result.get("risk_level", "low")
                }
                
                if ssti_result["vulnerable"]:
                    logger.info(f"[阶段2: 漏洞检测] 发现SSTI漏洞: {ssti_result['engine']}")
                    logger.info(f"风险等级: {ssti_result['risk_level']}")
                else:
                    logger.info(f"[阶段2: 漏洞检测] 未发现SSTI漏洞")
                    
                success = True
                return ssti_result
                
            except Exception as e:
                logger.error(f"[阶段2: 漏洞检测] 解析结果时发生错误: {e}")
                return {"error": f"Failed to parse result: {e}", "success": False}
        else:
            # API 调用本身失败了
            logger.error(f"[阶段2: 漏洞检测] SSTI检测失败: {url}，错误: {result.get('error')}")
            return result
            
    except Exception as e:
        error_msg = f"SSTI检测过程中发生错误: {str(e)}"
        logger.error(f"[阶段2: 漏洞检测] {error_msg}")
        return {
            "success": False,
            "error": error_msg,
            "vulnerable": False
        }
        
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        result = ssti_result if success else error_msg
        if result is None:
            result = 'No result' if success else 'Detection failed'
        log_tool_result("ssti_detection", result, duration, success)


# ========================================
# 阶段4：高级模糊测试工具
# ========================================

@mcp.tool()
async def ai_generate_payload(attack_type: str, complexity: str = "basic",
                        technology: str = "", url: str = "") -> Dict[str, Any]:
    """
    [阶段4: 高级模糊测试] AI驱动的上下文载荷生成器

    利用大模型的智能，生成针对特定上下文的载荷。
    - 用于测试: 命令注入, SSTI, XXE, SSRF, NoSQLI, 反序列化等

    Args:
        attack_type: 攻击类型 (xss, sqli, lfi, cmd_injection, ssti, xxe, ssrf, nosqli, deserialization)
        complexity: 复杂度级别 (basic, advanced, bypass)
        technology: 目标技术 (php, asp, jsp, python, nodejs)
        url: 目标URL用于上下文

    Returns:
        上下文载荷，包含风险评估和测试用例
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("ai_generate_payload", {
            "attack_type": attack_type,
            "complexity": complexity,
            "technology": technology,
            "url": url
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "attack_type": attack_type,
            "complexity": complexity,
            "technology": technology,
            "url": url
        }
        logger.info(f"[阶段4: 高级模糊测试] 为 {attack_type} 攻击生成AI载荷")
        result = client.safe_post("api/ai/generate_payload", data)

        if result.get("success"):
            payload_data = result.get("ai_payload_generation", {})
            count = payload_data.get("payload_count", 0)
            logger.info(f"[阶段4: 高级模糊测试] 生成了 {count} 个上下文 {attack_type} 载荷")

            # 记录一些示例载荷供用户了解
            payloads = payload_data.get("payloads", [])
            if payloads:
                logger.info(f"[阶段4: 高级模糊测试] 生成的示例载荷:")
                for i, payload_info in enumerate(payloads[:3]):  # 显示前3个
                    risk = payload_info.get("risk_level", "UNKNOWN")
                    context = payload_info.get("context", "basic")
                    logger.info(f"   ├─ [{risk}] {context}: {payload_info['payload'][:50]}...")
            success = True
        else:
            logger.error(f"[阶段4: 高级模糊测试] AI载荷生成失败")

        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("ai_generate_payload", tool_result, duration, success)


@mcp.tool()
async def http_repeater(request_spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    [阶段4: 高级模糊测试] HTTP Repeater (Burp Repeater替代品)

    发送精心构造的请求，用于测试复杂的漏洞。
    常与 ai_generate_payload 配合使用。

    Args:
        request_spec: 包含请求详细信息的字典
                      键: url, method, headers, cookies, data, params

    Returns:
        精心构造请求的响应
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        target_url = request_spec.get("url", "")
        log_tool_call("http_repeater", {
            "request_spec": {k: v for k, v in request_spec.items() if k != "data"}
        }, target_url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        payload = {"action": "repeater", "request": request_spec}
        logger.info(f"[阶段4: 高级模糊测试] 通过HTTP Repeater发送精心构造的请求")
        result = client.safe_post("api/tools/http-framework", payload)
        success = True
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("http_repeater", tool_result, duration, success)


@mcp.tool()
async def http_intruder(url: str, method: str = "GET", location: str = "query",
                  params: Optional[List[Any]] = None, payloads: Optional[List[Any]] = None,
                  headers: Optional[Dict[str, str]] = None, max_requests: int = 100) -> Dict[str, Any]:
    """
    [阶段4: 高级模糊测试] HTTP Intruder (Burp Intruder替代品)

    简单Intruder（狙击手）模糊测试。
    逐个在每个参数上迭代载荷。
    location: query|body|headers|cookie.

    Args:
        url: 目标URL
        method: HTTP方法
        location: 模糊测试位置 (query, body, headers, cookie)
        params: 要模糊测试的参数
        payloads: 要使用的载荷
        headers: 额外的HTTP头
        max_requests: 最大请求数

    Returns:
        模糊测试结果
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("http_intruder", {
            "url": url,
            "method": method,
            "location": location,
            "params": params or [],
            "payloads_count": len(payloads or []),
            "headers": headers or {},
            "max_requests": max_requests
        }, url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        payload = {
            "action": "intruder",
            "url": url,
            "method": method,
            "location": location,
            "params": params or [],
            "payloads": payloads or [],
            "headers": headers or {},
            "max_requests": max_requests
        }
        logger.info(f"[阶段4: 高级模糊测试] 启动HTTP Intruder模糊测试: {url}")
        result = client.safe_post("api/tools/http-framework", payload)
        success = True
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("http_intruder", tool_result, duration, success)


# ========================================
# 阶段5：特定服务与逻辑工具
# ========================================

@mcp.tool()
async def file_upload_testing(target_url: str) -> Dict[str, Any]:
    """
    [阶段5: 特定服务与逻辑] 文件上传漏洞测试工作流

    创建文件上传漏洞测试工作流，包含绕过技术。
    - 对应 "ARBITRARY_FILE_UPLOAD" 漏洞

    Args:
        target_url: 具有文件上传功能的目标URL

    Returns:
        文件上传测试工作流，包含恶意文件和绕过技术
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("file_upload_testing", {
            "target_url": target_url
        }, target_url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {"target_url": target_url}
        logger.info(f"[阶段5: 特定服务与逻辑] 为 {target_url} 创建文件上传测试工作流")
        result = client.safe_post("api/bugbounty/file-upload-testing", data)
        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("test_phases", []))
            logger.info(f"[阶段5: 特定服务与逻辑] 文件上传测试工作流已创建 - {phases} 个测试阶段")
            success = True
        else:
            logger.error(f"[阶段5: 特定服务与逻辑] 为 {target_url} 创建文件上传测试工作流失败")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("file_upload_testing", tool_result, duration, success)


@mcp.tool()
async def graphql_scanner(endpoint: str, introspection: bool = True,
                    query_depth: int = 10, test_mutations: bool = True) -> Dict[str, Any]:
    """
    [阶段5: 特定服务与逻辑] GraphQL安全扫描器

    高级GraphQL安全扫描和内省。

    Args:
        endpoint: GraphQL端点URL
        introspection: 测试内省查询
        query_depth: 要测试的最大查询深度
        test_mutations: 测试变异操作

    Returns:
        GraphQL安全扫描结果，包含漏洞评估
    """
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("graphql_scanner", {
            "endpoint": endpoint,
            "introspection": introspection,
            "query_depth": query_depth,
            "test_mutations": test_mutations
        }, endpoint)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "endpoint": endpoint,
            "introspection": introspection,
            "query_depth": query_depth,
            "test_mutations": test_mutations
        }
        logger.info(f"[阶段5: 特定服务与逻辑] 启动GraphQL安全扫描: {endpoint}")
        result = client.safe_post("api/tools/graphql_scanner", data)

        if result.get("success"):
            scan_results = result.get("graphql_scan_results", {})
            vuln_count = len(scan_results.get("vulnerabilities", []))
            tests_count = len(scan_results.get("tests_performed", []))

            logger.info(f"[阶段5: 特定服务与逻辑] GraphQL扫描完成: {tests_count} 个测试, {vuln_count} 个漏洞")

            if vuln_count > 0:
                logger.warning(f"[阶段5: 特定服务与逻辑] 发现 {vuln_count} 个GraphQL漏洞!")
                for vuln in scan_results.get("vulnerabilities", [])[:3]:  # 显示前3个
                    severity = vuln.get("severity", "UNKNOWN")
                    vuln_type = vuln.get("type", "unknown")
                    logger.info(f"   ├─ [{severity}] {vuln_type}")
            success = True
        else:
            logger.error(f"[阶段5: 特定服务与逻辑] GraphQL扫描失败")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("graphql_scanner", tool_result, duration, success)


@mcp.tool()
async def business_logic_testing(test_scenario: str, target_url: str,
                           auth_cookies: Optional[Dict[str, str]] = None,
                           test_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [阶段5: 特定服务与逻辑] 业务逻辑测试

    测试高度依赖上下文的漏洞：业务逻辑、权限提升、竞态条件等。
    这些漏洞需要大模型分析上下文并制定测试计划。

    Args:
        test_scenario: 测试场景描述
        target_url: 目标URL
        auth_cookies: 认证Cookie
        test_data: 测试数据

    Returns:
        业务逻辑测试结果
    """
    import json as json_module
    start_time = time.time()
    success = False
    try:
        # 记录工具调用
        log_tool_call("business_logic_testing", {
            "test_scenario": test_scenario,
            "target_url": target_url,
            "auth_cookies_count": len(auth_cookies or {}),
            "test_data_count": len(test_data or {})
        }, target_url)

        client = get_hexstrike_client()
        if not client:
            error_msg = "HexStrike client not available. Please set HEXSTRIKE_SERVER_URL environment variable."
            return {"error": error_msg, "success": False}

        data = {
            "test_scenario": test_scenario,
            "target_url": target_url,
            "auth_cookies": auth_cookies or {},
            "test_data": test_data or {}
        }
        logger.info(f"[阶段5: 特定服务与逻辑] 启动业务逻辑测试: {test_scenario}")
        logger.info(f"[阶段5: 特定服务与逻辑] 目标: {target_url}")

        # 使用http_repeater进行业务逻辑测试
        payload = {
            "action": "repeater",
            "request": {
                "url": target_url,
                "method": "POST",
                "headers": {
                    "Cookie": "; ".join([f"{k}={v}" for k, v in (auth_cookies or {}).items()])
                },
                "data": json_module.dumps(test_data) if test_data else ""
            },
            "test_type": "business_logic",
            "scenario": test_scenario
        }

        result = client.safe_post("api/tools/http-framework", payload)
        if result.get("success"):
            logger.info(f"[阶段5: 特定服务与逻辑] 业务逻辑测试完成")
            findings = result.get("findings", [])
            if findings:
                logger.warning(f"[阶段5: 特定服务与逻辑] 发现 {len(findings)} 个业务逻辑问题")
            success = True
        else:
            logger.error(f"[阶段5: 特定服务与逻辑] 业务逻辑测试失败")
        return result
    finally:
        # 记录工具执行结果
        duration = time.time() - start_time
        tool_result = result if success else result
        log_tool_result("business_logic_testing", tool_result, duration, success)


# ========================================
# 工具获取函数（用于外部调用）
# ========================================

def get_mcp_instance() -> FastMCP:
    """
    获取 MCP 实例（用于测试或外部调用）
    """
    return mcp


def run_mcp_server():
    """
    启动 MCP 服务器（可由外部调用）
    """
    import logging
    from config import setup_logging
    setup_logging()

    print("\n" + "=" * 60)
    print("HexStrike CTF Tools MCP Server")
    print("=" * 60)
    print()
    print("Starting FastMCP server with stdio transport...")
    print()

    mcp.run(transport='stdio')


if __name__ == "__main__":
    run_mcp_server()
