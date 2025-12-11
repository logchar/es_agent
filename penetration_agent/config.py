# coding:utf-8
"""
配置模块：管理客户端初始化、环境变量和基础配置
"""
from dotenv import load_dotenv
load_dotenv()

import os
import logging


def setup_logging():
    """设置日志配置 - 使用新的JSON结构化日志系统"""
    from logging_config import LoggerManager

    # 初始化JSON结构化日志系统
    # DEBUG模式启用详细日志记录
    LoggerManager.initialize(log_dir="logs", debug_mode=True)


def create_openai_client():
    """
    创建OpenAI客户端的工厂函数
    需要时才调用，避免在模块加载时就导入openai依赖
    """
    from openai import AsyncOpenAI, DefaultAsyncHttpxClient

    # 从环境变量安全地加载 API 密钥（使用 SiliconFlow）
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("错误：OPENAI_API_KEY 环境变量未设置！")
        print("请设置 DouBao API Key")
        exit(1)

    # 检查并配置代理
    proxy_url = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
    http_client_instance = None

    if proxy_url:
        print(f"检测到代理: {proxy_url}")
        print("正在创建 httpx 客户端，并使其自动从环境变量读取代理...")
        http_client_instance = DefaultAsyncHttpxClient()
    else:
        print("未检测到代理，将进行直连")
        http_client_instance = None

    # 初始化客户端
    base_url = os.getenv("OPENAI_BASE_URL", "https://ark.cn-beijing.volces.com/api/v3/")
    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        http_client=http_client_instance
    )

    return client


try:
    client = create_openai_client()
except Exception as e:
    print(f"创建OpenAI客户端失败: {e}")
    print("CTF工具可能仍然可用，但AI功能将不可用")
    client = None
