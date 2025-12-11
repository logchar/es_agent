from dataclasses import dataclass
from typing import Dict


@dataclass
class QuantitativeMetrics:
    """定量评估指标（由评估算法计算）"""
    total_tokens: int = 0
    total_time_seconds: float = 0.0
    total_requests: int = 0
    avg_response_time: float = 0.0
    token_efficiency: float = 0.0
    completion_rate: float = 0.0
    step_coverage: float = 0.0
    
@dataclass
class QualitativeMetrics:
    """定性评估指标（由评估AI Agent评估）"""
    task_understanding: float = 0.0
    planning_quality: float = 0.0
    code_quality: float = 0.0
    creativity: float = 0.0
    adaptability: float = 0.0
    overall_strategy: float = 0.0
    prompt_sensitivity: float = 0.0
    
@dataclass
class OverallScore:
    """综合评估得分"""
    quantitative_score: float = 0.0
    qualitative_score: float = 0.0
    overall_score: float = 0.0
    quantitative_breakdown: Dict[str, float] = None
    qualitative_breakdown: Dict[str, float] = None
    
    def __post_init__(self):
        if self.quantitative_breakdown is None:
            self.quantitative_breakdown = {}
        if self.qualitative_breakdown is None:
            self.qualitative_breakdown = {}
