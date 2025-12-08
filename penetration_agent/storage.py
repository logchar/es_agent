# coding:utf-8
"""
存储模块：管理线程本地存储、使用情况追踪和状态管理
"""
import threading
from datetime import datetime, timezone
import json
import logging
from typing import Dict, Any, List

from logging_config import get_logger

# 使用新的结构化日志系统
logger = get_logger("storage")

# 线程本地存储
_thread_local = threading.local()

def get_current_usage_tracker():
    """Get the usage tracker for the current thread/scan."""
    return getattr(_thread_local, 'usage_tracker', None)

def set_current_usage_tracker(tracker):
    """Set the usage tracker for the current thread/scan."""
    _thread_local.usage_tracker = tracker

def set_current_target_url(url):
    """Set the target URL for the current thread/scan."""
    _thread_local.current_target_url = url

def get_current_target_url():
    """Get the target URL for the current thread/scan."""
    return getattr(_thread_local, 'current_target_url', '')

# Usage tracking
class UsageTracker:
    def __init__(self):
        self.main_agent_usage = []
        self.agent_usage = []
        self.start_time = datetime.now(timezone.utc)

    def log_main_agent_usage(self, usage_data, target_url=""):
        """Log usage data from main agent responses."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_url": target_url,
            "agent_type": "main_agent",
            "usage": usage_data
        }
        self.main_agent_usage.append(entry)
        logging.info(f"Main Agent Usage - Target: {target_url}, Usage: {usage_data}")

    def log_agent_usage(self, usage_data, target_url=""):
        """Log usage data from agent responses."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_url": target_url,
            "agent_type": "agent",
            "usage": usage_data
        }
        self.agent_usage.append(entry)
        logging.info(f"Agent Usage - Target: {target_url}, Usage: {usage_data}")

    def get_summary(self):
        """Get usage summary for all agents."""
        return {
            "scan_duration": str(datetime.now(timezone.utc) - self.start_time),
            "main_agent_calls": len(self.main_agent_usage),
            "agent_calls": len(self.agent_usage),
            "total_calls": len(self.main_agent_usage) + len(self.agent_usage),
            "main_agent_usage": self.main_agent_usage,
            "agent_usage": self.agent_usage
        }

    def save_to_file(self, filename_prefix=""):
        """Save usage data to JSON file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}usage_log_{timestamp}.json"

        with open(filename, "w", encoding='utf-8') as f:
            json.dump(self.get_summary(), f, indent=2, default=str)

        logging.info(f"Usage data saved to {filename}")
        return filename


# ========================================
# ChallengeContext 题目上下文管理器
# ========================================

class ChallengeContext:
    """
    题目上下文管理器 - 确保多题目间完全隔离

    该类提供线程安全的上下文管理，确保：
    1. 每个题目有独立的发现列表
    2. 目标URL不会混淆
    3. 使用统计不会累积
    4. 日志带有题目标识符
    """

    _thread_local = threading.local()

    @classmethod
    def get_current_context(cls):
        """获取当前线程的上下文"""
        if not hasattr(cls._thread_local, 'context'):
            cls._thread_local.context = {}
        return cls._thread_local.context

    @classmethod
    def set_context(cls, context: Dict[str, Any]):
        """设置当前线程的上下文"""
        cls._thread_local.context = context

    @classmethod
    def clear_context(cls):
        """清理当前线程的上下文"""
        if hasattr(cls._thread_local, 'context'):
            delattr(cls._thread_local, 'context')

    @classmethod
    def start_challenge(cls, challenge_code: str, target_url: str):
        """
        开始新题目 - 自动清理旧上下文并设置新上下文

        Args:
            challenge_code: 题目代码，如 "XBEN-078-24"
            target_url: 目标URL，如 "http://192.168.1.100:8080"
        """
        cls.clear_context()
        cls.set_context({
            "challenge_code": challenge_code,
            "target_url": target_url,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "usage": []
        })
        logger.info(f"[题目开始] {challenge_code} (目标: {target_url})")

    @classmethod
    def end_challenge(cls):
        """结束当前题目 - 清理上下文"""
        if hasattr(cls._thread_local, 'context'):
            challenge_code = cls._thread_local.context.get("challenge_code", "unknown")
            findings_count = len(cls._thread_local.context.get("findings", []))
            cls.clear_context()
            logger.info(f"[题目结束] {challenge_code} (发现: {findings_count} 条)")

    @classmethod
    def add_finding(cls, finding: Dict[str, Any]):
        """添加发现到当前题目上下文"""
        context = cls.get_current_context()
        context.setdefault("findings", []).append(finding)

    @classmethod
    def get_findings(cls) -> List[Dict[str, Any]]:
        """获取当前题目的所有发现"""
        return cls.get_current_context().get("findings", [])

    @classmethod
    def get_challenge_code(cls) -> str:
        """获取当前题目代码"""
        return cls.get_current_context().get("challenge_code", "unknown")

    @classmethod
    def get_target_url(cls) -> str:
        """获取当前目标URL"""
        return cls.get_current_context().get("target_url", "")

    @classmethod
    def add_usage(cls, usage_data: Dict[str, Any]):
        """添加使用统计到当前题目上下文"""
        context = cls.get_current_context()
        context.setdefault("usage", []).append(usage_data)

    @classmethod
    def get_usage(cls) -> List[Dict[str, Any]]:
        """获取当前题目的使用统计"""
        return cls.get_current_context().get("usage", [])

    @classmethod
    def log_with_challenge(cls, level: int, message: str):
        """
        带题目上下文的日志记录

        Args:
            level: 日志级别 (logging.INFO, logging.WARNING, etc.)
            message: 日志消息
        """
        challenge_code = cls.get_challenge_code()
        target_url = cls.get_target_url()

        # 格式化日志消息
        log_message = f"[{challenge_code}] {message}"
        if target_url:
            log_message = f"[{challenge_code}] ({target_url}) {message}"

        # 记录日志
        logger.log(level, log_message)

    @classmethod
    def get_context_summary(cls) -> Dict[str, Any]:
        """获取当前题目的上下文摘要"""
        context = cls.get_current_context()
        return {
            "challenge_code": context.get("challenge_code"),
            "target_url": context.get("target_url"),
            "start_time": context.get("start_time"),
            "findings_count": len(context.get("findings", [])),
            "usage_count": len(context.get("usage", []))
        }
