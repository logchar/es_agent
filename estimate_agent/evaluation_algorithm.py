import re
from datetime import datetime
from typing import Dict, List
import statistics
from collections import defaultdict
from data_class import QuantitativeMetrics


class EvaluationAlgorithm:
    """评估算法 - 计算定量指标"""
    
    def __init__(self, log_data: List[Dict]):
        self.log_data = log_data
        self.start_time = None
        self.end_time = None
        self.total_tokens = 0
        self.tool_calls = []
        self.phase_activities = defaultdict(list)
        
    def parse_logs(self):
        """解析日志数据，提取关键信息"""
        events = []
        
        for entry in self.log_data:
            event_type = entry.get("event", "")
            timestamp = entry.get("timestamp", "")
            phase = entry.get("phase", 0)
            
            # 解析时间戳
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except:
                dt = None
                
            # 提取token相关信息
            if "llm_request" in event_type:
                messages_count = entry.get("messages_count", 0)
                # 估算token数：每条消息约100-200 tokens
                estimated_tokens = messages_count * 150
                self.total_tokens += estimated_tokens
                
            elif "llm_response" in event_type:
                tool_calls = entry.get("tool_calls_count", 0)
                if tool_calls > 0:
                    tool_name = self._extract_tool_name(entry)
                    self.tool_calls.append(tool_name)
                    
                # 估算响应token数
                response_preview = entry.get("response_preview", "")
                reasoning = self._extract_reasoning(entry)
                estimated_tokens = len(str(response_preview) + str(reasoning)) // 4
                self.total_tokens += estimated_tokens
                
            # 记录事件
            if dt:
                events.append((dt, entry))
                
        # 计算时间跨度
        if events:
            events.sort(key=lambda x: x[0])
            self.start_time = events[0][0]
            self.end_time = events[-1][0]
            
    def _extract_tool_name(self, entry: Dict) -> str:
        """从日志中提取工具名称"""
        preview = str(entry.get("response_preview", ""))
        if "whatweb_scan" in preview:
            return "whatweb_scan"
        elif "dirsearch_scan" in preview:
            return "dirsearch_scan"
        elif "run_python" in preview:
            return "run_python"
        elif "http_repeater" in preview:
            return "http_repeater"
        return "unknown"
        
    def _extract_reasoning(self, entry: Dict) -> str:
        """从日志中提取推理内容"""
        preview = str(entry.get("response_preview", ""))
        if "reasoning_content" in preview:
            # 提取reasoning_content部分
            match = re.search(r"reasoning_content='(.*?)'", preview)
            if match:
                return match.group(1)
        return ""
        
    def calculate_quantitative_metrics(self) -> QuantitativeMetrics:
        """计算所有定量指标"""
        if not self.log_data:
            return QuantitativeMetrics()
            
        self.parse_logs()
        
        # 计算总用时
        total_time = 0.0
        if self.start_time and self.end_time:
            total_time = (self.end_time - self.start_time).total_seconds()
            
        # 计算平均响应时间
        response_times = []
        request_time = None
        
        for entry in self.log_data:
            event = entry.get("event", "")
            timestamp = entry.get("timestamp", "")
            
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except:
                continue
                
            if "llm_request" in event:
                request_time = dt
            elif "llm_response" in event and request_time:
                response_time = (dt - request_time).total_seconds()
                response_times.append(response_time)
                request_time = None
                
        avg_response_time = statistics.mean(response_times) if response_times else 0.0
        
        # 计算完成度（基于渗透测试步骤）
        penetration_steps = [
            "reconnaissance",  # 侦察
            "scanning",        # 扫描
            "exploitation",    # 利用
            "maintaining_access",  # 维持访问
            "reporting"        # 报告
        ]
        
        # 从日志中推断执行了哪些步骤
        executed_steps = set()
        
        # 检查工具调用来推断步骤
        for tool in self.tool_calls:
            if tool in ["whatweb_scan", "dirsearch_scan"]:
                executed_steps.add("reconnaissance")
                executed_steps.add("scanning")
            elif "run_python" in tool:
                executed_steps.add("exploitation")
            elif "http_repeater" in tool:
                executed_steps.add("exploitation")
                
        # 检查是否尝试了登录（从推理内容推断）
        for entry in self.log_data:
            preview = str(entry.get("response_preview", ""))
            if "login" in preview.lower() or "password" in preview.lower():
                executed_steps.add("exploitation")
                
        step_coverage = len(executed_steps) / len(penetration_steps) if penetration_steps else 0.0
        
        # 计算token效率（工具调用数 / token数）
        token_efficiency = len(self.tool_calls) / self.total_tokens if self.total_tokens > 0 else 0.0
        
        return QuantitativeMetrics(
            total_tokens=self.total_tokens,
            total_time_seconds=total_time,
            total_requests=len(self.log_data) // 2,  # 每对请求-响应算一次请求
            avg_response_time=avg_response_time,
            token_efficiency=token_efficiency * 1000,  # 乘以1000使数值更易读
            completion_rate=step_coverage * 100,  # 转换为百分比
            step_coverage=step_coverage
        )