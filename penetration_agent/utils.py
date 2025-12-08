def extract_flag_from_result(result: str) -> str:
    """从解题结果中提取flag"""
    import re
    # 严格的flag格式匹配（UUID格式：8-4-4-4-12位十六进制）
    flag_patterns = [
        r'flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}',  # flag{UUID}
        r'FLAG\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}',  # FLAG{UUID}
    ]
    for pattern in flag_patterns:
        match = re.search(pattern, result)
        if match:
            return match.group(0)
    return None
