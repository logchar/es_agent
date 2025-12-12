import re
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class EvaluationResult:
    """评估结果数据类"""
    score: float
    reasoning: str
    confidence: float

class LLMEvaluator:
    """LLM评估器基类"""
    
    def __init__(self, client: Any, model: str = "doubao-seed-1-6-251015"):
        self.client = client
        self.model = model
        self.temperature = 0.1  # 低温度以获得更一致的评估
        
    async def evaluate_with_prompt(self, prompt: str, context: Dict) -> EvaluationResult:
        """使用LLM进行评估的核心方法"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个专业的AI Agent评估专家。请根据评估标准对给定的内容进行客观、准确的评分。"},
                    {"role": "user", "content": prompt.format(**context)}
                ],
                temperature=self.temperature,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content
            return self._parse_evaluation_result(result_text)
            
        except Exception as e:
            # 评估失败时返回默认分数
            return EvaluationResult(
                score=5.0,
                reasoning=f"评估过程中发生错误: {str(e)}",
                confidence=0.1
            )
    
    def _parse_evaluation_result(self, result_text: str) -> EvaluationResult:
        """解析LLM返回的评估结果"""
        # 尝试提取分数和推理过程
        score_match = re.search(r'评分[：:]\s*(\d+(?:\.\d+)?)/10', result_text)
        reasoning_match = re.search(r'理由[：:](.*?)(?=评分|$)', result_text, re.DOTALL)
        
        if score_match:
            score = float(score_match.group(1))
            reasoning = reasoning_match.group(1).strip() if reasoning_match else "未提供详细理由"
        else:
            # 如果无法解析，使用默认值
            score = 5.0
            reasoning = "无法解析评估结果，使用默认评分"
        
        # 基于响应质量计算置信度
        confidence = min(len(result_text) / 100, 1.0)
        
        return EvaluationResult(score=score, reasoning=reasoning, confidence=confidence)
    