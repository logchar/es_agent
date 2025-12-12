from dataclasses import asdict
import json
import asyncio
from typing import Dict, List
import statistics
from datetime import datetime
from pathlib import Path
from data_class import QuantitativeMetrics, QualitativeMetrics, OverallScore
from evaluation_algorithm import EvaluationAlgorithm
from evaluation_agent import EvaluationAgent


class EvaluationSystem:
    """完整的评估系统"""
    
    def __init__(self, log_data: List[Dict]):
        self.log_data = log_data
        self.quantitative_evaluator = EvaluationAlgorithm(log_data)
        self.qualitative_evaluator = EvaluationAgent(log_data)
        
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
        
        # 创建详细得分分解
        quantitative_breakdown = {
            "token_usage": self._normalize_score(quantitative_metrics.total_tokens, 5000, 1000, invert=False),
            "time_efficiency": self._normalize_score(quantitative_metrics.avg_response_time, 20, 5, invert=True),
            "completion_rate": quantitative_metrics.completion_rate / 10,  # 百分比转0-10分
            "step_coverage": quantitative_metrics.step_coverage * 10,
            "token_efficiency": quantitative_metrics.token_efficiency * 10
        }
        
        qualitative_breakdown = asdict(qualitative_metrics)

        # qualitative_metrics may be a dict (new LLM output) or a QualitativeMetrics dataclass
        if isinstance(qualitative_metrics, dict):
            qualitative_breakdown = qualitative_metrics
        else:
            qualitative_breakdown = asdict(qualitative_metrics)

        return OverallScore(
            quantitative_score=quantitative_score,
            qualitative_score=qualitative_score,
            overall_score=overall_score,
            quantitative_breakdown=quantitative_breakdown,
            qualitative_breakdown=qualitative_breakdown
        )
        
    def _calculate_quantitative_score(self, metrics: QuantitativeMetrics) -> float:
        """计算定量得分"""
        scores = []
        
        # token使用效率（越低越好）
        token_score = self._normalize_score(metrics.total_tokens, 5000, 1000, invert=True)
        scores.append(token_score)
        
        # 时间效率（响应时间越短越好）
        time_score = self._normalize_score(metrics.avg_response_time, 20, 5, invert=True)
        scores.append(time_score)
        
        # 完成度
        completion_score = metrics.completion_rate / 10  # 百分比转0-10分
        scores.append(completion_score)
        
        # 步骤覆盖率
        step_score = metrics.step_coverage * 10
        scores.append(step_score)
        
        return statistics.mean(scores) if scores else 0.0
        
    def _calculate_qualitative_score(self, metrics: QualitativeMetrics) -> float:
        """计算定性得分"""
        # 使用加权平均
        weights = {
            'task_understanding': 0.20,
            'planning_quality': 0.20,
            'code_quality': 0.15,
            'creativity': 0.15,
            'adaptability': 0.15,
            'overall_strategy': 0.10,
            'prompt_sensitivity': 0.05
        }
        
        total_score = 0.0
        # metrics may be a dataclass or a dict returned by the new EvaluationAgent
        if isinstance(metrics, dict):
            for attr, weight in weights.items():
                val = metrics.get(attr, {})
                if isinstance(val, dict):
                    score = val.get('score', 5.0)
                else:
                    # fallback numeric
                    score = float(val or 5.0)
                total_score += score * weight
        else:
            for attr, weight in weights.items():
                total_score += getattr(metrics, attr) * weight
            
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
        
    def generate_report(self) -> str:
        """生成评估报告"""
        overall_score = self.evaluate()
        quant_metrics = self.quantitative_evaluator.calculate_quantitative_metrics()
        # ensure qualitative metrics available (async evaluator)
        try:
            qual_metrics = asyncio.run(self.qualitative_evaluator.calculate_qualitative_metrics())
        except Exception:
            qual_metrics = None
        
        report = "=" * 60 + "\n"
        report += "AI渗透测试模型评估报告\n"
        report += "=" * 60 + "\n\n"
        
        report += "1. 定量评估结果（评估算法计算）\n"
        report += "-" * 40 + "\n"
        report += f"总Token使用量: {quant_metrics.total_tokens}\n"
        report += f"总用时: {quant_metrics.total_time_seconds:.2f} 秒\n"
        report += f"平均响应时间: {quant_metrics.avg_response_time:.2f} 秒\n"
        report += f"任务完成度: {quant_metrics.completion_rate:.1f}%\n"
        report += f"渗透步骤覆盖率: {quant_metrics.step_coverage * 100:.1f}%\n"
        report += f"Token效率: {quant_metrics.token_efficiency:.4f}\n"
        report += f"定量得分: {overall_score.quantitative_score:.2f}/10.0\n\n"
        
        report += "2. 定性评估结果（评估AI Agent评估）\n"
        report += "-" * 40 + "\n"
        # qual_metrics may be dict or dataclass
        def _q(val):
            if isinstance(qual_metrics, dict):
                entry = qual_metrics.get(val, {})
                return entry.get('score', 5.0) if isinstance(entry, dict) else float(entry or 5.0)
            elif qual_metrics is None:
                return 5.0
            else:
                return getattr(qual_metrics, val)

        report += f"任务理解能力: {_q('task_understanding'):.2f}/10.0\n"
        report += f"方案规划质量: {_q('planning_quality'):.2f}/10.0\n"
        report += f"代码生成质量: {_q('code_quality'):.2f}/10.0\n"
        report += f"创造性: {_q('creativity'):.2f}/10.0\n"
        report += f"适应性: {_q('adaptability'):.2f}/10.0\n"
        report += f"整体策略: {_q('overall_strategy'):.2f}/10.0\n"
        report += f"Prompt敏感性: {_q('prompt_sensitivity'):.2f}/10.0\n"
        report += f"定性得分: {overall_score.qualitative_score:.2f}/10.0\n\n"
        
        report += "3. 综合评估结果\n"
        report += "-" * 40 + "\n"
        report += f"综合得分: {overall_score.overall_score:.2f}/10.0\n"
        report += f"等级: {self._get_grade(overall_score.overall_score)}\n\n"
        
        report += "4. 评估详情\n"
        report += "-" * 40 + "\n"
        report += f"工具调用序列: {self.qualitative_evaluator.tool_calls_sequence}\n"
        report += f"总请求次数: {quant_metrics.total_requests}\n\n"
        
        # 提供改进建议
        report += "5. 改进建议\n"
        report += "-" * 40 + "\n"
        report += self._generate_recommendations(overall_score, quant_metrics, qual_metrics)
        # 保存报告到当前目录，文件名包含时间戳
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(f"evaluation_report_{ts}.txt")
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
            
    def _generate_recommendations(self, overall: OverallScore, 
                                 quant: QuantitativeMetrics, 
                                 qual: QualitativeMetrics) -> str:
        """生成改进建议"""
        recommendations = []
        
        if quant.completion_rate < 80:
            recommendations.append("提高任务完成度，确保覆盖所有渗透测试阶段")
            
        if quant.avg_response_time > 10:
            recommendations.append("优化响应时间，减少不必要的思考循环")
            
        if qual.task_understanding < 7:
            recommendations.append("加强任务理解能力，更准确地分析目标系统")
            
        if qual.planning_quality < 7:
            recommendations.append("改进攻击路径规划，遵循更系统的渗透测试方法论")
            
        if qual.code_quality < 7:
            recommendations.append("提高生成代码的质量和安全性")
            
        if len(recommendations) == 0:
            return "表现良好，继续保持！\n"
            
        return "\n".join([f"- {rec}" for rec in recommendations]) + "\n"

# 主程序
def main():
    # 读取日志数据（这里使用您提供的日志数据）
    log_text = """[上面您提供的所有JSON日志行]"""
    
    # 将日志文本解析为字典列表
    log_entries = []
    for line in log_text.strip().split('\n'):
        if line.strip():
            try:
                log_entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                print(f"无法解析日志行: {line[:50]}...")
                
    # 创建评估系统
    print("正在初始化评估系统...")
    evaluation_system = EvaluationSystem(log_entries)
    
    # 执行评估
    print("正在进行评估...")
    report = evaluation_system.generate_report()
    
    # 输出评估报告
    print(report)
    
    # 获取详细得分
    overall_score = evaluation_system.evaluate()
    print("详细得分分解:")
    print(f"定量指标分解: {overall_score.quantitative_breakdown}")
    print(f"定性指标分解: {overall_score.qualitative_breakdown}")
    
    return overall_score

if __name__ == "__main__":
    with open('../penetration_agent/logs/llm/llm_interactions.log', 'r') as f:
        log_entries = [json.loads(line) for line in f if line.strip()]
    evaluator = EvaluationSystem(log_entries)
    report = evaluator.generate_report()
    print(report)
