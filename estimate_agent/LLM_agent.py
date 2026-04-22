import re
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

@dataclass
class EvaluationResult:
    """评估结果数据类"""
    score: float
    reasoning: str
    confidence: float
    meta: Optional[Dict[str, Any]] = None

class LLMEvaluator:
    """LLM评估器基类"""
    
    def __init__(self, client: Any, model):
        self.client = client
        self.model = model
        self.temperature = 0.1  # 低温度以获得更一致的评估
        # 记录评估模型自身的调用开销（用于定量统计）
        self.call_records: List[Dict[str, Any]] = []
        
    async def evaluate_with_prompt(self, prompt: str, context: Dict) -> EvaluationResult:
        """使用LLM进行评估的核心方法"""
        try:
            if not self.client:
                raise RuntimeError("LLM client not available")

            # Align with common critic fine-tune system prompts while keeping Chinese safety constraint.
            system_msg = (
                "You are a penetration-testing run critic. Compare the agent's run against the reference solution. "
                "Provide a score and reasons. Do NOT provide exploit payloads or step-by-step attack instructions. "
                "Focus on evaluation. "
                "你是专业的渗透测试过程评估模型，只做评价与诊断，不提供payload、利用细节或可执行攻击步骤。"
            )
            user_msg = prompt.format(**context)
            start_t = time.perf_counter()

            # Await the async client call
            resp = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg}
                ],
                temperature=self.temperature,
                max_tokens=500
            )

            latency_s = max(0.0, time.perf_counter() - start_t)

            # Extract text robustly depending on response shape
            result_text = None
            try:
                result_text = resp.choices[0].message.content
            except Exception:
                try:
                    result_text = resp.choices[0].text
                except Exception:
                    result_text = str(resp)

            # usage (if available)
            usage = getattr(resp, "usage", None)
            prompt_tokens = None
            completion_tokens = None
            total_tokens = None
            try:
                prompt_tokens = int(getattr(usage, "prompt_tokens", None)) if usage is not None else None
                completion_tokens = int(getattr(usage, "completion_tokens", None)) if usage is not None else None
                total_tokens = int(getattr(usage, "total_tokens", None)) if usage is not None else None
            except Exception:
                prompt_tokens = completion_tokens = total_tokens = None

            if total_tokens is None:
                # fallback heuristic: chars/4
                prompt_tokens = max(1, (len(system_msg) + len(user_msg)) // 4)
                completion_tokens = max(1, len(result_text or "") // 4)
                total_tokens = int(prompt_tokens + completion_tokens)

            record = {
                "model": self.model,
                "latency_seconds": latency_s,
                "prompt_tokens": int(prompt_tokens) if prompt_tokens is not None else 0,
                "completion_tokens": int(completion_tokens) if completion_tokens is not None else 0,
                "total_tokens": int(total_tokens) if total_tokens is not None else 0,
            }
            self.call_records.append(record)

            parsed = self._parse_evaluation_result(result_text)
            parsed.meta = record
            return parsed
            
        except Exception as e:
            # 评估失败时返回默认分数
            return EvaluationResult(
                score=5.0,
                reasoning=f"评估过程中发生错误: {str(e)}",
                confidence=0.1,
                meta={"model": self.model, "error": str(e)}
            )
    
    def _parse_evaluation_result(self, result_text: str) -> EvaluationResult:
        """解析LLM返回的评估结果"""
        # 尝试提取分数和推理过程
        text = result_text or ""

        # Optional explicit confidence (common in fine-tuned critics)
        confidence = None
        for p in [
            r'\[CONFIDENCE\]\s*([01](?:\.\d+)?)',
            r'置信度[：:]\s*([01](?:\.\d+)?)',
            r'confidence[：:]\s*([01](?:\.\d+)?)',
        ]:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                try:
                    confidence = float(m.group(1))
                    break
                except Exception:
                    continue

        # 优先匹配更明确的总体得分表达（含 fine-tune 常见格式）
        score = None
        score_pos = None
        patterns = [
            r'\[SCORE\]\s*(\d+(?:\.\d+)?)(?:\s*/\s*10)?',
            r'评分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?',
            r'综合评分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?',
            r'总分[：:]\s*(\d+(?:\.\d+)?)(?:分|/10)?',
            r'score[：:]\s*(\d+(?:\.\d+)?)(?:\s*/\s*10)?',
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

        # 进一步兼容：任意出现的 “x/10”
        if score is None:
            m = re.search(r'(\d+(?:\.\d+)?)\s*/\s*10', text)
            if m:
                try:
                    score = float(m.group(1))
                    score_pos = m.end()
                except Exception:
                    score = None

        if score is None:
            score = 5.0

        # Clamp into [0, 10]
        try:
            score = float(score)
        except Exception:
            score = 5.0
        score = max(0.0, min(10.0, score))

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

        # If reasoning is still unhelpful (e.g., starts with tags), try to extract common critic sections.
        if reasoning and (reasoning.startswith('[CONFIDENCE]') or reasoning.startswith('[TRACK]') or reasoning.startswith('[MATCHED_STEP]')):
            reasoning = ""

        if not reasoning:
            section_labels = [
                'Summary',
                'Evidence',
                'Deviations',
                'Deviations / Missing',
                'Run snapshot',
                'Minimal corrections',
            ]

            blocks = []
            for lab in section_labels:
                # Capture from "<lab>:" up to next section header or tag block
                m = re.search(
                    rf'{re.escape(lab)}\s*:\s*(.*?)(?=\n(?:[A-Z][A-Za-z /]+\s*:|\[[A-Z_]+\])|$)',
                    text,
                    re.DOTALL,
                )
                if m:
                    content = m.group(1).strip()
                    if content:
                        blocks.append(f"{lab}:\n{content}")

            if blocks:
                reasoning = "\n\n".join(blocks)
            else:
                reasoning = "未提供详细理由"

        # 置信度：优先使用显式字段，否则基于响应长度估计，并限制在0-1之间
        if confidence is None:
            confidence = min(len(text) / 800, 1.0)
        else:
            confidence = max(0.0, min(1.0, confidence))

        return EvaluationResult(score=score, reasoning=reasoning, confidence=confidence)
    