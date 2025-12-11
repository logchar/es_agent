# coding:utf-8
"""
日志配置模块：JSON结构化日志系统
支持日志轮转、分类存储、DEBUG模式详细记录
"""
import json
import logging
import logging.handlers
import os
from datetime import datetime
from typing import Any, Dict, Optional

# ========================================
# JSON格式化器
# ========================================

class JSONFormatter(logging.Formatter):
    """自定义JSON格式化器，将日志记录转换为结构化JSON"""

    def format(self, record: logging.LogRecord) -> str:
        """将日志记录格式化为JSON字符串"""
        # 基础日志信息
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # 添加异常信息
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info)
            }

        # 添加自定义字段
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        return json.dumps(log_data, ensure_ascii=False, default=str)


class ColoredConsoleFormatter(logging.Formatter):
    """带颜色的控制台格式化器（仅用于开发调试）"""

    # 颜色代码
    grey = '\x1b[38;21m'
    yellow = '\x1b[33;21m'
    red = '\x1b[31;21m'
    bold_red = '\x1b[31;1m'
    blue = '\x1b[34;21m'
    green = '\x1b[32;21m'
    reset = '\x1b[0m'

    FORMATS = {
        logging.DEBUG: grey + "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s" + reset,
        logging.INFO: blue + "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s" + reset,
        logging.WARNING: yellow + "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s" + reset,
        logging.ERROR: red + "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s" + reset,
        logging.CRITICAL: bold_red + "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s" + reset
    }

    def format(self, record: logging.LogRecord) -> str:
        log_format = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
        formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

# ========================================
# 日志轮转配置
# ========================================

class SizedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """自定义大小轮转文件处理器"""

    def __init__(self, filename, maxBytes=500*1024*1024, backupCount=5, **kwargs):
        """
        初始化文件处理器

        Args:
            filename: 日志文件名
            maxBytes: 最大文件大小（字节），默认500MB
            backupCount: 保留的备份文件数量
        """
        super().__init__(filename, maxBytes=maxBytes, backupCount=backupCount, **kwargs)

# ========================================
# 日志管理器
# ========================================

class LoggerManager:
    """日志管理器 - 统一管理所有日志记录器"""

    _loggers = {}
    _handlers = {}
    _initialized = False

    @classmethod
    def initialize(cls, log_dir: str = "logs", debug_mode: bool = True):
        """初始化日志系统"""
        if cls._initialized:
            return

        # 创建日志目录
        os.makedirs(log_dir, exist_ok=True)

        # 创建子目录
        os.makedirs(f"{log_dir}/tools", exist_ok=True)
        os.makedirs(f"{log_dir}/llm", exist_ok=True)
        os.makedirs(f"{log_dir}/app", exist_ok=True)

        # 设置全局日志级别
        log_level = logging.DEBUG if debug_mode else logging.INFO
        logging.getLogger().setLevel(log_level)

        # 1. 创建通用应用日志记录器
        app_logger = logging.getLogger("app")
        app_logger.setLevel(log_level)

        # 通用日志文件处理器
        app_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/app/application.log",
            maxBytes=500*1024*1024,  # 500MB
            backupCount=5
        )
        app_file_handler.setFormatter(JSONFormatter())

        # 通用控制台处理器
        if debug_mode:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(ColoredConsoleFormatter())
            app_logger.addHandler(console_handler)

        app_logger.addHandler(app_file_handler)
        cls._handlers['app'] = app_file_handler
        cls._loggers['app'] = app_logger

        # 2. 创建工具日志记录器
        tools_logger = logging.getLogger("tools")
        tools_logger.setLevel(log_level)

        # 工具日志文件处理器
        tools_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/tools/tools_execution.log",
            maxBytes=500*1024*1024,  # 500MB
            backupCount=5
        )
        tools_file_handler.setFormatter(JSONFormatter())
        tools_logger.addHandler(tools_file_handler)
        cls._handlers['tools'] = tools_file_handler
        cls._loggers['tools'] = tools_logger

        # 3. 创建大模型日志记录器
        llm_logger = logging.getLogger("llm")
        llm_logger.setLevel(log_level)

        # 大模型日志文件处理器
        llm_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/llm/llm_interactions.log",
            maxBytes=500*1024*1024,  # 500MB
            backupCount=5
        )
        llm_file_handler.setFormatter(JSONFormatter())
        llm_logger.addHandler(llm_file_handler)
        cls._handlers['llm'] = llm_file_handler
        cls._loggers['llm'] = llm_logger

        # 4. 创建MCP服务器日志记录器
        mcp_logger = logging.getLogger("mcp")
        mcp_logger.setLevel(log_level)
        mcp_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/app/mcp_server.log",
            maxBytes=500*1024*1024,
            backupCount=5
        )
        mcp_file_handler.setFormatter(JSONFormatter())
        mcp_logger.addHandler(mcp_file_handler)
        cls._handlers['mcp'] = mcp_file_handler
        cls._loggers['mcp'] = mcp_logger

        # 5. 创建CTF API日志记录器
        ctf_logger = logging.getLogger("hexstrike-ctf-api")
        ctf_logger.setLevel(log_level)
        ctf_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/app/ctf_api.log",
            maxBytes=500*1024*1024,
            backupCount=5
        )
        ctf_file_handler.setFormatter(JSONFormatter())
        ctf_logger.addHandler(ctf_file_handler)
        cls._handlers['ctf'] = ctf_file_handler
        cls._loggers['ctf'] = ctf_logger

        # 6. 创建存储追踪日志记录器
        storage_logger = logging.getLogger("storage")
        storage_logger.setLevel(log_level)
        storage_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/app/storage.log",
            maxBytes=500*1024*1024,
            backupCount=5
        )
        storage_file_handler.setFormatter(JSONFormatter())
        storage_logger.addHandler(storage_file_handler)
        cls._handlers['storage'] = storage_file_handler
        cls._loggers['storage'] = storage_logger

        # 7. 创建阶段代理日志记录器
        phase_logger = logging.getLogger("phase_agents")
        phase_logger.setLevel(log_level)
        phase_file_handler = SizedRotatingFileHandler(
            f"{log_dir}/app/phase_agents.log",
            maxBytes=500*1024*1024,
            backupCount=5
        )
        phase_file_handler.setFormatter(JSONFormatter())
        phase_logger.addHandler(phase_file_handler)
        cls._handlers['phase'] = phase_file_handler
        cls._loggers['phase'] = phase_logger

        # 防止日志向上传播到根记录器
        logging.getLogger("tools").propagate = False
        logging.getLogger("llm").propagate = False
        logging.getLogger("mcp").propagate = False
        logging.getLogger("hexstrike-ctf-api").propagate = False
        logging.getLogger("storage").propagate = False
        logging.getLogger("phase_agents").propagate = False

        cls._initialized = True

        # 记录初始化日志
        if debug_mode:
            extra = {"event": "logging_init"}
            record = app_logger.makeRecord(
                app_logger.name, logging.INFO, "", 0,
                "日志系统初始化完成 - DEBUG模式", (), None
            )
            record.extra_fields = extra
            app_logger.handle(record)

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """获取指定名称的日志记录器"""
        if not cls._initialized:
            cls.initialize()
        return cls._loggers.get(name, logging.getLogger(name))

    @classmethod
    def log_tool_call(cls, tool_name: str, arguments: Dict[str, Any], target_url: str = ""):
        """记录工具调用（结构化）"""
        logger = cls.get_logger("tools")
        # 使用LogRecord的__dict__传递额外字段
        extra = {
            "event": "tool_call",
            "tool_name": tool_name,
            "arguments": arguments,
            "target_url": target_url
        }
        # 创建一个带有额外字段的LogRecord
        record = logger.makeRecord(
            logger.name, logging.INFO, "", 0,
            f"工具调用: {tool_name}", (), None
        )
        record.extra_fields = extra
        logger.handle(record)

    @classmethod
    def log_tool_result(cls, tool_name: str, result: Any, duration: float, success: bool):
        """记录工具执行结果（结构化）"""
        logger = cls.get_logger("tools")
        status = "success" if success else "failed"

        # 记录完整结果，不进行截断
        if isinstance(result, (str, dict, list)):
            # 对于复杂数据类型，转换为JSON字符串
            result_str = json.dumps(result, ensure_ascii=False, default=str)
        else:
            result_str = str(result)

        extra = {
            "event": "tool_result",
            "tool_name": tool_name,
            "status": status,
            "duration_ms": round(duration * 1000, 2),
            "result": result_str  # 改为完整结果字段
        }
        record = logger.makeRecord(
            logger.name, logging.INFO, "", 0,
            f"工具执行完成: {tool_name} - {status}", (), None
        )
        record.extra_fields = extra
        logger.handle(record)

    @classmethod
    def log_llm_request(cls, messages: list, model: str, phase: int, max_rounds: int):
        """记录大模型请求（结构化）"""
        logger = cls.get_logger("llm")
        extra = {
            "event": "llm_request",
            "model": model,
            "phase": phase,
            "max_rounds": max_rounds,
            "messages_count": len(messages),
            "messages_preview": [
                {"role": m.get("role"), "content_length": len(str(m.get("content", "")))}
                for m in messages[:3]
            ]
        }
        record = logger.makeRecord(
            logger.name, logging.INFO, "", 0,
            f"LLM请求: 阶段{phase} - {model}", (), None
        )
        record.extra_fields = extra
        logger.handle(record)

    @classmethod
    def log_llm_response(cls, response: Any, phase: int, tool_calls_count: int):
        """记录大模型响应（结构化）"""
        logger = cls.get_logger("llm")
        extra = {
            "event": "llm_response",
            "phase": phase,
            "tool_calls_count": tool_calls_count,
            "response_preview": str(response)[:1000] if response else None
        }
        record = logger.makeRecord(
            logger.name, logging.INFO, "", 0,
            f"LLM响应: 阶段{phase} - 工具调用: {tool_calls_count}", (), None
        )
        record.extra_fields = extra
        logger.handle(record)

    @classmethod
    def log_phase_start(cls, phase: int, phase_name: str, target_url: str):
        """记录阶段开始"""
        logger = cls.get_logger("phase")
        extra = {
            "event": "phase_start",
            "phase": phase,
            "phase_name": phase_name,
            "target_url": target_url
        }
        record = logger.makeRecord(
            logger.name, logging.INFO, "", 0,
            f"开始执行阶段 {phase}: {phase_name}", (), None
        )
        record.extra_fields = extra
        logger.handle(record)

    @classmethod
    def log_phase_end(cls, phase: int, phase_name: str, success: bool, findings_count: int):
        """记录阶段结束"""
        logger = cls.get_logger("phase")
        status = "success" if success else "failed"
        extra = {
            "event": "phase_end",
            "phase": phase,
            "phase_name": phase_name,
            "status": status,
            "findings_count": findings_count
        }
        record = logger.makeRecord(
            logger.name, logging.INFO, "", 0,
            f"阶段 {phase} 执行完成: {phase_name} - {status}", (), None
        )
        record.extra_fields = extra
        logger.handle(record)

# ========================================
# 便捷函数
# ========================================

def get_logger(name: str = "app") -> logging.Logger:
    """获取日志记录器的便捷函数"""
    return LoggerManager.get_logger(name)

def log_tool_call(tool_name: str, arguments: Dict[str, Any], target_url: str = ""):
    """记录工具调用的便捷函数"""
    LoggerManager.log_tool_call(tool_name, arguments, target_url)

def log_tool_result(tool_name: str, result: Any, duration: float, success: bool):
    """记录工具执行结果的便捷函数"""
    LoggerManager.log_tool_result(tool_name, result, duration, success)

def log_llm_request(messages: list, model: str, phase: int, max_rounds: int):
    """记录大模型请求的便捷函数"""
    LoggerManager.log_llm_request(messages, model, phase, max_rounds)

def log_llm_response(response: Any, phase: int, tool_calls_count: int):
    """记录大模型响应的便捷函数"""
    LoggerManager.log_llm_response(response, phase, tool_calls_count)

def log_phase_start(phase: int, phase_name: str, target_url: str):
    """记录阶段开始的便捷函数"""
    LoggerManager.log_phase_start(phase, phase_name, target_url)

def log_phase_end(phase: int, phase_name: str, success: bool, findings_count: int):
    """记录阶段结束的便捷函数"""
    LoggerManager.log_phase_end(phase, phase_name, success, findings_count)
