import re
from datetime import datetime
from typing import Dict, List
import statistics
from collections import defaultdict
from .data_class import QuantitativeMetrics


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
        # 尽量从显式字段中提取
        if not isinstance(entry, dict):
            return "unknown"

        # 优先使用显式字段
        tool_name_field = entry.get("tool_name") or entry.get("tool") or entry.get("name")
        if isinstance(tool_name_field, str) and tool_name_field:
            return tool_name_field

        # 支持 tool_calls 结构（列表/字典）
        tc = entry.get("tool_calls") or entry.get("tool_calls_count")
        if isinstance(tc, list) and tc:
            first = tc[0]
            if isinstance(first, dict) and first.get("name"):
                return first.get("name")
            if isinstance(first, str):
                return first

        preview = str(entry.get("response_preview", "") or "").lower()
        content = str(entry.get("content", "") or "").lower()
        combined = preview + " " + content

        # 映射常用工具关键词到规范名称（基于 phase_agents system_prompt 列表）
        mapping = [
            ("whatweb_scan", "whatweb"),
            ("dirsearch_scan", "dirsearch"),
            ("katana_crawl", "katana"),
            ("arjun_parameter_discovery", "arjun"),
            ("nuclei_scan", "nuclei"),
            ("sqlmap_scan", "sqlmap"),
            ("dalfox_xss_scan", "dalfox"),
            ("dotdotpwn_scan", "dotdotpwn"),
            ("hydra_attack", "hydra"),
            ("jwt_analyzer", "jwt"),
            ("idor_testing", "idor"),
            ("http_repeater", "repeater"),
            ("http_intruder", "intruder"),
            ("file_upload_testing", "upload"),
            ("ai_generate_payload", "ai_generate_payload"),
            ("graphql_scanner", "graphql"),
            ("business_logic_testing", "business_logic"),
            ("run_python", "run_python"),
            ("run_command", "run_command")
        ]

        for name, key in mapping:
            if key in combined:
                return name

        # 常见后缀/前缀匹配
        if "scan" in combined:
            m = re.search(r"(\w+)_scan", combined)
            if m:
                return m.group(0)

        # 最后尝试匹配工具单词
        for kw in ["whatweb", "dirsearch", "nuclei", "sqlmap", "dalfox", "hydra", "graphql", "intruder", "repeater", "arjun", "katana", "dotdotpwn", "jwt", "idor"]:
            if kw in combined:
                # 返回较规范的名称
                return kw + ("_scan" if kw in ("nuclei", "whatweb", "dirsearch", "dotdotpwn") else "")

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
        
        # ========================计算总用时
        total_time = 0.0
        if self.start_time and self.end_time:
            total_time = (self.end_time - self.start_time).total_seconds()
            
        # ========================计算平均响应时间========================
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
        
        return QuantitativeMetrics(
            total_tokens=self.total_tokens,
            total_time_seconds=total_time,
            total_requests=len(self.log_data) // 2,  # 每对请求-响应算一次请求
            avg_response_time=avg_response_time
        )
    