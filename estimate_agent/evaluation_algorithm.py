import re
from datetime import datetime
from typing import Dict, List, Optional, Any
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

        # 评估模型（judge/critic）自身的调用开销（可选，由 EvaluationAgent/LLMEvaluator 提供）
        self.eval_call_records: List[Dict[str, Any]] = []
        
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
                
            # 提取 token 相关信息（渗透模型侧）
            if event_type == "llm_request" or "llm_request" in event_type:
                messages_count = int(entry.get("messages_count", 0) or 0)
                preview = entry.get("messages_preview") or []
                # messages_preview 仅记录了前3条消息的长度；以其均值外推总长度
                try:
                    lengths = [int(m.get("content_length", 0) or 0) for m in preview if isinstance(m, dict)]
                except Exception:
                    lengths = []
                if lengths:
                    avg_len = statistics.mean(lengths)
                    total_chars = int(sum(lengths) + max(0, messages_count - len(lengths)) * avg_len)
                    estimated_tokens = max(1, total_chars // 4)
                else:
                    # fallback：无长度信息时按条数粗估
                    estimated_tokens = max(1, messages_count * 150)
                self.total_tokens += int(estimated_tokens)
                
            elif event_type == "llm_response" or "llm_response" in event_type:
                tool_calls = entry.get("tool_calls_count", 0)
                if tool_calls > 0:
                    tool_name = self._extract_tool_name(entry)
                    self.tool_calls.append(tool_name)
                    
                # 估算响应token数
                response_preview = entry.get("response_preview", "")
                reasoning = self._extract_reasoning(entry)
                estimated_tokens = max(1, len(str(response_preview) + str(reasoning)) // 4)
                self.total_tokens += int(estimated_tokens)
                
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
            # 仍返回评估模型侧的统计（如果存在）
            return self._build_metrics_from_current_state()
            
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
        

        # 评估模型侧统计（来自 call_records）
        eval_total_tokens = int(sum(int(r.get("total_tokens", 0) or 0) for r in self.eval_call_records))
        eval_total_time_seconds = float(sum(float(r.get("latency_seconds", 0.0) or 0.0) for r in self.eval_call_records))
        eval_total_requests = int(len(self.eval_call_records))
        eval_avg_response_time = float(
            statistics.mean([float(r.get("latency_seconds", 0.0) or 0.0) for r in self.eval_call_records])
        ) if self.eval_call_records else 0.0

        return QuantitativeMetrics(
            # penetration / target model
            total_tokens=int(self.total_tokens),
            total_time_seconds=float(total_time),
            total_requests=int(sum(1 for e in self.log_data if (e.get("event") == "llm_request" or "llm_request" in str(e.get("event", ""))))),
            avg_response_time=float(avg_response_time),
            # evaluator model
            eval_total_tokens=eval_total_tokens,
            eval_total_time_seconds=eval_total_time_seconds,
            eval_total_requests=eval_total_requests,
            eval_avg_response_time=eval_avg_response_time,
        )

    def _build_metrics_from_current_state(self) -> QuantitativeMetrics:
        """当 penetration log 为空时，仅基于 eval_call_records 构建指标。"""
        eval_total_tokens = int(sum(int(r.get("total_tokens", 0) or 0) for r in self.eval_call_records))
        eval_total_time_seconds = float(sum(float(r.get("latency_seconds", 0.0) or 0.0) for r in self.eval_call_records))
        eval_total_requests = int(len(self.eval_call_records))
        eval_avg_response_time = float(
            statistics.mean([float(r.get("latency_seconds", 0.0) or 0.0) for r in self.eval_call_records])
        ) if self.eval_call_records else 0.0

        return QuantitativeMetrics(
            total_tokens=0,
            total_time_seconds=0.0,
            total_requests=0,
            avg_response_time=0.0,
            eval_total_tokens=eval_total_tokens,
            eval_total_time_seconds=eval_total_time_seconds,
            eval_total_requests=eval_total_requests,
            eval_avg_response_time=eval_avg_response_time,
        )

    def set_eval_call_records(self, records: Optional[List[Dict[str, Any]]]):
        """注入评估模型的调用记录（由 EvaluationAgent/LLMEvaluator 产生）。"""
        self.eval_call_records = list(records or [])
    