from dataclasses import asdict
import json
import asyncio
from typing import Dict, List
import statistics
from datetime import datetime
from pathlib import Path
from .data_class import QuantitativeMetrics, QualitativeMetrics, OverallScore
from .evaluation_algorithm import EvaluationAlgorithm
from .evaluation_agent import EvaluationAgent
import os
from dotenv import load_dotenv
load_dotenv()


class EvaluationSystem:
    """完整的评估系统"""
    
    def __init__(self, log_data: List[Dict]):
        self.log_data = log_data
        self.quantitative_evaluator = EvaluationAlgorithm(log_data)
        self.qualitative_evaluator = EvaluationAgent(log_data, os.getenv("OPENAI_MODEL_NAME"))
        
    def evaluate(self) -> OverallScore:
        """执行完整评估"""
        # 计算定量指标
        quantitative_metrics = self.quantitative_evaluator.calculate_quantitative_metrics()
        
        # 计算定性指标
        # qualitative evaluator is async; run it and accept dict result
        try:
            qualitative_metrics = asyncio.run(self.qualitative_evaluator.calculate_qualitative_metrics())
        except Exception:
            # fallback: empty/default values
            qualitative_metrics = None
        
        # 计算定量得分（0-10分）
        quantitative_score = self._calculate_quantitative_score(quantitative_metrics)
        
        # 计算定性得分（0-10分）
        qualitative_score = self._calculate_qualitative_score(qualitative_metrics)
        
        # 计算综合得分（定量40%，定性60%）
        overall_score = (quantitative_score * 0.4) + (qualitative_score * 0.6)
            
            # 创建详细得分分解 - 量化子项得分
        try:
            token_score = self._normalize_score(getattr(quantitative_metrics, 'total_tokens', 0), 2000000, 10000, invert=False)
            total_time_score = self._normalize_score(getattr(quantitative_metrics, 'total_time_seconds', 0.0), 1000.0, 60.0, invert=False)
            requests_score = self._normalize_score(getattr(quantitative_metrics, 'total_requests', 0), 100, 5, invert=False)
            avg_resp_score = self._normalize_score(getattr(quantitative_metrics, 'avg_response_time', 0.0), 20.0, 2.0, invert=False)
            quantitative_breakdown = {
                'token_score': token_score,
                'total_time_score': total_time_score,
                'requests_score': requests_score,
                'avg_response_time_score': avg_resp_score
            }
        except Exception:
            quantitative_breakdown = asdict(quantitative_metrics) if quantitative_metrics is not None else {}
        
        # qualitative_metrics may be a dict (new LLM output) or a QualitativeMetrics dataclass
        if isinstance(qualitative_metrics, dict):
            qualitative_breakdown = qualitative_metrics
        else:
            # if None or a dataclass, convert to dict (dataclass -> dict; None -> empty dict)
            qualitative_breakdown = asdict(qualitative_metrics) if qualitative_metrics is not None else {}

        return OverallScore(
            quantitative_score=quantitative_score,
            qualitative_score=qualitative_score,
            overall_score=overall_score,
            quantitative_breakdown=quantitative_breakdown,
            qualitative_breakdown=qualitative_breakdown,
            quantitative_metrics=quantitative_metrics,
            qualitative_metrics=qualitative_metrics
        )
        
    def _calculate_quantitative_score(self, metrics: QuantitativeMetrics) -> float:
        """计算定量得分"""
        # 基于新的 QuantitativeMetrics，只使用四个指标：
        # total_tokens, total_time_seconds, total_requests, avg_response_time
        scores = []

        # token 使用量（越少越好）
        token_score = self._normalize_score(getattr(metrics, 'total_tokens', 0), 2000000, 10000, invert=False)
        scores.append(token_score)

        # 总用时（越少越好）
        total_time_score = self._normalize_score(getattr(metrics, 'total_time_seconds', 0.0), 1000.0, 60.0, invert=False)
        scores.append(total_time_score)

        # 总请求数（越少越好，代表更有效的交互）
        requests_score = self._normalize_score(getattr(metrics, 'total_requests', 0), 100, 5, invert=False)
        scores.append(requests_score)

        # 平均响应时间（越短越好）
        avg_resp_score = self._normalize_score(getattr(metrics, 'avg_response_time', 0.0), 20.0, 2.0, invert=False)
        scores.append(avg_resp_score)

        return statistics.mean(scores) if scores else 0.0
        
    def _calculate_qualitative_score(self, metrics: QualitativeMetrics) -> float:
        """计算定性得分"""
        # 使用加权平均，包含由 EvaluationAgent 额外计算的 completion_rate 和 token_efficiency
        weights = {
            'task_understanding': 0.18,
            'planning_quality': 0.18,
            'code_quality': 0.14,
            'creativity': 0.12,
            'adaptability': 0.12,
            'prompt_sensitivity': 0.04,
            'completion_rate': 0.14,
            'token_efficiency': 0.08
        }

        total_score = 0.0
        # metrics may be a dataclass or a dict returned by the EvaluationAgent
        if isinstance(metrics, dict):
            for attr, weight in weights.items():
                val = metrics.get(attr, {})
                if isinstance(val, dict):
                    score = val.get('score', 5.0)
                else:
                    try:
                        score = float(val)
                    except Exception:
                        score = 5.0
                # 如果是百分比（如 completion_rate/token_efficiency），将其缩放到0-10
                if attr in ('completion_rate', 'token_efficiency'):
                    score = score / 10.0
                total_score += score * weight
        else:
            for attr, weight in weights.items():
                val = getattr(metrics, attr, 5.0)
                if attr in ('completion_rate', 'token_efficiency'):
                    val = val / 10.0
                total_score += float(val) * weight

        return total_score
        
    def _normalize_score(self, value: float, max_val: float, ideal_val: float, invert: bool = False) -> float:
        """归一化分数到0-10分"""
        if value <= ideal_val:
            score = 10.0
        else:
            # 线性下降
            score = max(0, 10 * (1 - (value - ideal_val) / (max_val - ideal_val)))
            
        if invert:
            score = 10 - score
            
        return score
        
    def generate_report(self, challenge_code: str = None, model_name: str = None) -> str:
        """生成评估报告"""
        overall_score = self.evaluate()
        quant_metrics = overall_score.quantitative_metrics
        qual_metrics = overall_score.qualitative_metrics
        
        report = "=" * 60 + "\n"
        report += "AI渗透测试模型评估报告\n"
        report += "=" * 60 + "\n\n"
        
        report += "1. 定量评估结果（评估算法计算）\n"
        report += "-" * 40 + "\n"
        report += f"总Token使用量: {quant_metrics.total_tokens}\n"
        report += f"总用时: {quant_metrics.total_time_seconds:.2f} 秒\n"
        report += f"总请求次数: {quant_metrics.total_requests}\n"
        report += f"平均响应时间: {quant_metrics.avg_response_time:.2f} 秒\n"
        report += f"定量得分: {overall_score.quantitative_score:.2f}/10.0\n\n"

        # 添加每个定量子项的得分（0-10）
        report += "定量子项得分:\n"
        qbd = overall_score.quantitative_breakdown or {}
        report += f"- Token 使用得分: {qbd.get('token_score', 0.0):.2f}/10.0\n"
        report += f"- 总耗时得分: {qbd.get('total_time_score', 0.0):.2f}/10.0\n"
        report += f"- 请求数量得分: {qbd.get('requests_score', 0.0):.2f}/10.0\n"
        report += f"- 平均响应时间得分: {qbd.get('avg_response_time_score', 0.0):.2f}/10.0\n"
        
        report += "2. 定性评估结果（评估AI Agent评估）\n"
        report += "-" * 40 + "\n"
        # qual_metrics may be dict or dataclass. Present per-dimension score, confidence and reasoning when available.
        def _qscore(name: str) -> float:
            if isinstance(qual_metrics, dict):
                v = qual_metrics.get(name, {})
                if isinstance(v, dict):
                    return float(v.get('score', 5.0))
                try:
                    return float(v)
                except Exception:
                    return 5.0
            if qual_metrics is None:
                return 5.0
            return float(getattr(qual_metrics, name, 5.0))

        def _qreason(name: str) -> str:
            if isinstance(qual_metrics, dict):
                v = qual_metrics.get(name, {})
                if isinstance(v, dict):
                    return v.get('reasoning', '')
                return ''
            return ''

        def _qconf(name: str) -> float:
            if isinstance(qual_metrics, dict):
                v = qual_metrics.get(name, {})
                if isinstance(v, dict):
                    return float(v.get('confidence', 0.0))
                return 0.0
            return 0.0

        # 更差异化地展示每个定性维度：分数、置信度、理由简述
        qualitative_items = [
            ('task_understanding', '任务理解能力'),
            ('planning_quality', '方案规划质量'),
            ('code_quality', '代码生成质量'),
            ('creativity', '创造性'),
            ('adaptability', '适应性'),
            ('prompt_sensitivity', 'Prompt敏感性'),
            ('completion_rate', '任务完成率'),
            ('token_efficiency', 'Token使用效率')
        ]

        for key, label in qualitative_items:
            score = _qscore(key)
            conf = _qconf(key)
            reason = _qreason(key)
            # 尽量只展示理由的前400个字符以保持报告紧凑
            reason_excerpt = (reason[:397] + '...') if reason and len(reason) > 200 else reason
            report += f"{label}: {score:.2f}/10.0  (confidence: {conf:.2f})\n"
            if reason_excerpt:
                report += f"理由: {reason_excerpt}\n"
            report += "\n"

        report += f"定性得分: {overall_score.qualitative_score:.2f}/10.0\n\n"
        
        report += "3. 综合评估结果\n"
        report += "-" * 40 + "\n"
        report += f"综合得分: {overall_score.overall_score:.2f}/10.0\n"
        report += f"等级: {self._get_grade(overall_score.overall_score)}\n\n"
        
        report += "4. 评估详情\n"
        report += "-" * 40 + "\n"
        report += f"工具调用序列: {self.qualitative_evaluator.tool_calls_sequence}\n"
        report += f"总请求次数: {quant_metrics.total_requests}\n\n"
        
        # 保存报告到当前目录，文件名包含时间戳
        output_dir = Path("eval_results")
        if not output_dir.exists():
            output_dir.mkdir(parents=True, exist_ok=True)

        if challenge_code and model_name:
            filename = output_dir / f"{challenge_code}_{model_name}.txt"
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = output_dir / f"evaluation_report_{ts}.txt"
        try:
            filename.write_text(report, encoding="utf-8")
        except Exception:
            # 若写入失败，仍返回报告字符串
            return report

        # 返回文件名而不是直接打印全部文本
        return str(filename)
        
    def _get_grade(self, score: float) -> str:
        """根据得分获取等级"""
        if score >= 9.0:
            return "优秀 (A+)"
        elif score >= 8.0:
            return "良好 (A)"
        elif score >= 7.0:
            return "中等 (B)"
        elif score >= 6.0:
            return "及格 (C)"
        else:
            return "不及格 (D)"

if __name__ == "__main__":
    with open('./penetration_agent/logs/llm/llm_interactions.log', 'r') as f:
        log_entries = [json.loads(line) for line in f if line.strip()]
    evaluator = EvaluationSystem(log_entries)
    
    challenge_codes = [e.get('challenge_code') for e in log_entries if e.get('challenge_code')]
    challenge_code = challenge_codes[0] if challenge_codes else "unknown_challenge"
    model_name = os.getenv("OPENAI_MODEL_NAME", "unknown_model")
    
    filename = evaluator.generate_report(challenge_code=challenge_code, model_name=model_name)
    print(filename)
