import os
import asyncio
import logging
import json
import time
import argparse
from typing import List, Dict, Any
from config import setup_logging
from storage import UsageTracker, set_current_usage_tracker, ChallengeContext
from logging_config import get_logger
from utils import extract_flag_from_result
import threading


async def run_ctf_challenge_phase_based(challenge_code: str, target_info: Dict[str, Any],
                                       max_rounds_per_phase: int = 50):
    """
    使用单Agent运行CTF解题流程

    Args:
        challenge_code: 题目代码
        target_info: 目标信息（包含IP和端口）
        max_rounds_per_phase: 最大轮数

    Returns:
        Dict: 解题结果
    """
    try:
        from phase_agents import PhaseManager

        logging.info(f"开始单Agent解题: {challenge_code}")
        logging.info(f"目标信息: {target_info}")

        # 构建target_url
        ip = target_info.get('ip')
        ports = target_info.get('port', [])
        if ports:
            target_url = f"http://{ip}:{ports[0]}"
        else:
            target_url = f"http://{ip}"

        # 启动题目上下文管理
        ChallengeContext.start_challenge(challenge_code, target_url)
        logging.info(f"✓ 启动题目上下文: {challenge_code}")

        # 创建单Agent管理器
        phase_manager = await PhaseManager.create_single_agent()
        logging.info("使用单Agent模式：单一代理掌握所有工具")

        instruction = f"""CTF题目: {challenge_code}
目标: {target_url}

请使用所有可用的渗透测试工具，系统性地测试目标以获取CTF flag。

注意：你的最终目标是获取flag格式的字符串（如 flag{{...}}）。"""

        result = await phase_manager.execute_single_agent(
            instruction=instruction,
            context={"target_url": target_url},
            max_rounds=max_rounds_per_phase
        )

        # 尝试从结果中提取flag
        flag = extract_flag_from_result(str(result))

        if flag:
            logging.info(f"找到flag: {flag}")

            return {
                "challenge_code": challenge_code,
                "target_url": target_url,
                "flag": flag,
                "found_in_phase": "UnifiedAgent",
                "results": {"unified": result},
                "status": "completed"
            }

        # 未找到flag，获取总结
        logging.info(f"未找到flag，获取解题总结...")
        summary = phase_manager.get_all_summaries()

        # 未找到flag，保存结果
        filename = f"{challenge_code}_single_agent_result.md"
        with open(filename, "w", encoding='utf-8') as f:
            f.write(f"{'='*80}\n")
            f.write(f"单Agent解题结果: {challenge_code}\n")
            f.write(f"{'='*80}\n\n")

            f.write(f"目标: {target_url}\n")
            f.write(f"总轮数: {max_rounds_per_phase}\n")

            f.write(f"{'='*80}\n")
            f.write("解题总结:\n")
            f.write(f"{'='*80}\n")
            f.write(str(summary))
            f.write("\n")

        return {
            "challenge_code": challenge_code,
            "target_url": target_url,
            "flag": None,
            "results": {
                "initial": result
            },
            "status": "no_flag",
            "filename": filename
        }

    except Exception as e:
        logging.error(f"阶段式解题失败 {challenge_code}: {e}", exc_info=True)
        return {
            "challenge_code": challenge_code,
            "target_url": target_url if 'target_url' in locals() else "",
            "flag": None,
            "status": "error",
            "error": str(e)
        }
    finally:
        # 结束题目上下文管理
        ChallengeContext.end_challenge()


async def main():
    # 设置日志
    setup_logging()

    result = await run_ctf_challenge_phase_based(
        challenge_code="XBEN-001-24",
        target_info={"ip": "127.0.0.1", "port": [32768]},
        max_rounds_per_phase=50
    )

    print(result)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
