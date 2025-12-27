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
            if not self.client:
                raise RuntimeError("LLM client not available")

            # Await the async client call
            resp = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个专业的AI Agent评估专家。请根据评估标准对给定的内容进行客观、准确的评分。"},
                    {"role": "user", "content": prompt.format(**context)}
                ],
                temperature=self.temperature,
                max_tokens=500
            )

            # Extract text robustly depending on response shape
            result_text = None
            try:
                result_text = resp.choices[0].message.content
            except Exception:
                try:
                    result_text = resp.choices[0].text
                except Exception:
                    result_text = str(resp)

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
        print(result_text)
        text = result_text or ""

        # 优先匹配更明确的总体得分表达
        score = None
        score_pos = None
        patterns = [
            r'综合评分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?',
            r'总分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?',
            r'评分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?'
        ]

        for p in patterns:
            m = re.search(p, text)
            if m:
                try:
                    score = float(m.group(1))
                    score_pos = m.end()
                    break
                except Exception:
                    continue

        # 如果还没找到，尝试找到最后一个出现的“评分”并取其值
        if score is None:
            for m in re.finditer(r'评分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?', text):
                try:
                    score = float(m.group(1))
                    score_pos = m.end()
                except Exception:
                    continue

        if score is None:
            score = 5.0

        # 优先在分数之后查找最近的理由区块；如果找不到则退回到全文搜索
        reasoning = None
        if score_pos:
            m = re.search(r'理由[：:]\s*(.*?)(?=(?:\n(?:综合评分|总分|评分)|$))', text[score_pos:], re.DOTALL)
            if m:
                reasoning = m.group(1).strip()

        if not reasoning:
            m = re.search(r'理由[：:]\s*(.*?)(?=(?:\n(?:综合评分|总分|评分)|$))', text, re.DOTALL)
            if m:
                reasoning = m.group(1).strip()

        if not reasoning:
            # 退一步，尝试取分数行之后的若干内容作为推理摘要
            if score_pos:
                tail = text[score_pos:].strip()
                reasoning = tail.split('\n\n')[0].strip() if tail else "未提供详细理由"
            else:
                reasoning = "未提供详细理由"

        # 基于响应长度计算置信度（越长通常信息越丰富），并限制在0-1之间
        confidence = min(len(text) / 1000, 1.0)

        return EvaluationResult(score=score, reasoning=reasoning, confidence=confidence)
    