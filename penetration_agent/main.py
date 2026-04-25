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


async def run_ctf_challenge_phase_based(challenge_code: str, target_info: Dict[str, Any]):
    """
    使用单Agent运行CTF解题流程（每题一次 ``claude -p`` 会话；对话轮次由环境变量
    ``CLAUDE_CODE_MAX_TURNS`` 控制，不再使用 Python 外层 for 多轮 continue）。

    Args:
        challenge_code: 题目代码
        target_info: 目标信息（包含IP和端口）

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
            context={"target_url": target_url, "challenge_code": challenge_code},
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
            f.write(f"说明: 对话轮次由环境变量 CLAUDE_CODE_MAX_TURNS 控制（无 Python 外层多轮）\n")

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
    challenges = {
        # "vulhub_01-rce_medium-web-1": {"ip": "222.20.126.52", "port": [32875]},
        "XBEN-009-24": {"ip": "localhost", "port": [32768]},
        # "XBEN-032-24": {"ip": "localhost", "port": [32779]},
        # "XBEN-036-24": {"ip": "localhost", "port": [32778]},
        # "XBEN-019-24": {"ip": "localhost", "port": [32777]}
    }
    
    # Claude SDK 优先，其次兼容旧的 CLAUDE_CODE_MODEL
    model_name = os.getenv("CLAUDE_SDK_MODEL") or os.getenv("CLAUDE_CODE_MODEL") or "unknown_model"
    
    # 循环处理每个挑战
    for challenge_code, target_info in challenges.items():
         # 设置日志（使用统一标识）
        setup_logging(challenge_code=challenge_code, model_name=model_name)

        print(f"\n开始处理挑战: {challenge_code}")
        logging.info(f"开始处理挑战: {challenge_code}")
        
        result = await run_ctf_challenge_phase_based(
            challenge_code=challenge_code,
            target_info=target_info,
        )
        
        print(f"挑战 {challenge_code} 处理结果: {result}")
    
    print("\n所有挑战处理完成！")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
