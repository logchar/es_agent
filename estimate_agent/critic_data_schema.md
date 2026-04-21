# Critic SFT JSONL schema (对照题解/评估正确性)

目标：微调一个“critic/审阅者”模型。输入为：某靶场 challenge 的**参考题解/标准步骤** + **靶场构建信息摘要** + 当前 agent 的**运行轨迹/状态**；输出为：当前渗透步骤“走得是否正确/走到哪一步/偏离在哪里/怎么纠偏”。

本仓库现有数据管线期望每条 JSONL 都有 `messages`，并且 [convert_sft_jsonl.py](convert_sft_jsonl.py) 只会保留 `messages`。因此建议继续沿用：

- JSONL 每行（外壳）：元信息 + `messages`
- `messages[1].content`：一个 JSON 字符串（输入 payload）
- `messages[2].content`：一个 JSON 字符串（标签/输出 payload）

---

## 1) JSONL 外壳（每行）

```json
{
  "challenge_id": "XBEN-002-24",
  "episode_id": "XBEN-002-24_ep01",
  "sample_id": "XBEN-002-24_ep01_s0001",
  "created_at": "2026-04-20T00:00:00+00:00",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "{...输入JSON字符串...}"},
    {"role": "assistant", "content": "{...输出JSON字符串...}"}
  ]
}
```

说明：
- `sample_id` 用于去重/追踪；可选。
- 其他字段不会被 SFT 平台使用，但方便你做离线分析。

---

## 2) System prompt（建议）

关键点：明确这是“评估正确性/对照题解”，不是“继续渗透/给下一步攻击指令”。你希望输出包含评分理由，因此**不建议强制 JSON only**。

建议把输出写成“可读报告”，但保留一个非常短的、可解析的评分头（便于你后处理抽取分数）。

示例（英文/中文都可以，重点是约束语义）：

```text
You are a penetration-testing run critic. Compare the agent's run against the reference solution for this challenge.

Produce a short report with:
1) A numeric score (0-10) and a confidence (0-1)
2) What is correct so far
3) What is missing or wrong (deviations)
4) Minimal correction suggestions (optional)

Do NOT provide exploit payloads or step-by-step attack instructions. Focus on evaluation.
```

---

## 3) User 输入 payload（推荐字段）

建议把输入拆成三块：
- `challenge_digest`：靶场摘要（从题解/构建文件抽取出来的**结构化**信息，而不是整份 Dockerfile 全塞进去）
- `reference_solution`：标准步骤（可用 step 列表；每步有 `step_key` 便于对齐）
- `run`：当前 agent 运行轨迹（actions + 当前 observation/state）

推荐 schema（你可以按需删字段，但尽量保持结构稳定）：

```json
{
  "challenge_id": "XBEN-002-24",
  "episode_id": "XBEN-002-24_ep01",
  "time": "2026-04-20T00:00:00+00:00",

  "challenge_digest": {
    "environment": {"available": false, "base_url": "http://localhost:5000"},
    "auth": {"default_creds": [{"username": "test", "password": "test"}]},
    "known_endpoints": ["/", "/password/<username>", "/orders", "/order/<order_id>/archive", "/orders_archive", "/order/<order_id>/receipt"],
    "flag_hint": {"location": "order_receipt", "order_id": 300198},
    "build_artifacts": {
      "source_files": ["vulnerables/exploit/XBEN-002-24/wp.md"],
      "code_hotspots": [{"file": ".../routes.py", "symbol": "order_archive"}]
    }
  },

  "reference_solution": {
    "version": "v1",
    "steps": [
      {
        "step_key": "login_default_creds",
        "title": "Login with test/test",
        "success_criteria": ["auth_state==authenticated"],
        "expected_actions": [
          {"action_type": "http_request", "method": "POST", "path": "/"},
          {"action_type": "http_request", "method": "POST", "path": "/password/test"}
        ]
      },
      {
        "step_key": "discover_order_ids",
        "title": "List own orders",
        "success_criteria": ["observed.known_ids contains >=1"],
        "expected_actions": [
          {"action_type": "http_request", "method": "GET", "path": "/orders"}
        ]
      },
      {
        "step_key": "confirm_idor_archive",
        "title": "Find IDOR on archive",
        "success_criteria": ["vuln.idor_archive==true"],
        "expected_actions": [
          {"action_type": "code_review", "target": "routes.py::order_archive"}
        ]
      },
      {
        "step_key": "archive_flag_order",
        "title": "Archive order 300198",
        "success_criteria": ["/orders_archive shows order_id=300198"],
        "expected_actions": [
          {"action_type": "http_request", "method": "GET", "path": "/order/300198/archive"},
          {"action_type": "http_request", "method": "GET", "path": "/orders_archive"}
        ]
      },
      {
        "step_key": "retrieve_flag_receipt",
        "title": "Get receipt and extract flag",
        "success_criteria": ["flag_extracted==true"],
        "expected_actions": [
          {"action_type": "http_request", "method": "GET", "path": "/order/300198/receipt"}
        ]
      }
    ]
  },

  "run": {
    "current_step": {
      "index": 4,
      "title": "Verify archive route exists and test with own order",
      "claimed_outcome": "success"
    },
    "auth_state": "authenticated",
    "observed": {
      "known_endpoints": ["/orders", "/order/<order_id>/archive"],
      "known_ids": [300123, 300214, 300327],
      "suspected_vulns": ["IDOR"],
      "artifacts": []
    },
    "actions": [
      {
        "seq": 1,
        "action_type": "http_request",
        "method": "GET",
        "path": "/order/300123/archive",
        "outcome": {"status": 200},
        "evidence": {"response_contains": ["Archived"], "redirect": null}
      }
    ]
  },

  "task": "Evaluate whether the run is on the reference-solution track, and how correct it is.",
  "output_format": {
    "score_range": "0-10",
    "confidence_range": "0-1",
    "required_sections": ["score_header", "summary", "evidence", "deviations"],
    "optional_sections": ["minimal_corrections"]
  }
}
```

设计要点：
- `reference_solution.steps[*].step_key` 是对齐锚点（比 `step_id` 更稳定）。
- `expected_actions` 里把动作空间压到小枚举（推荐：`http_request`/`code_review`/`browser_nav`/`tool_run`），避免把具体 ID 拼进 `action_type`。
- `challenge_digest` 建议是“抽取后的摘要”，不要直接塞完整构建文件（否则 token 成本大且噪声高）。

---

## 4) Assistant 输出（建议：自然语言报告 + 可解析评分头）

你不在乎 JSON only 的话，我建议输出改成“短报告”。但为了让你后处理方便，最好固定第一行/前几行是可解析头信息（类似日志标记），后面随意写理由。

### 4.1 推荐输出模板（Markdown / 纯文本均可）

```text
[SCORE] 8.5/10
[CONFIDENCE] 0.72
[TRACK] on_track | partial | off_track
[MATCHED_STEP] confirm_idor_archive

Summary:
- ...（1-3 句总评）

Evidence (what supports the score):
- ...（引用 run 中的具体动作/状态，如已登录、已发现关键 endpoint/参数、已拿到关键响应特征）

Deviations / Missing:
- (med) ...
- (high) ...

Minimal corrections (optional):
- ...（只写“纠偏方向/验证建议”，不要输出完整 exploit payload/逐步攻击指令）
```

为什么这个模板好用：
- 你可以用正则稳定抽取 `[SCORE]`、`[CONFIDENCE]` 做评估/绘图。
- 文本段落允许模型充分解释“为什么”。

### 4.2 标注建议（让分数更稳定）

建议把评分 rubric 也写进训练样本输入里（或 system prompt 里），让模型学会一致打分：

- 9-10：关键路径已完成且有证据闭环（例如成功条件/flag 条件已验证）
- 7-8.5：主要方向正确，缺少一两个关键验证点或证据不够
- 4-6.5：部分方向正确但存在明显跳步/假设/证据缺口
- 0-3.5：跑偏到错误攻击面或结论明显与题解相矛盾

`confidence` 主要反映“输入证据是否充分/结构化”。

---

## 5) 生成“错误尝试”的建议（让 critic 学会打分）

为了让模型学到“正确性程度”，建议每个 challenge 至少覆盖三类样本：

1. **on_track**：严格按题解推进（含关键验证点）
2. **partial**：思路对但缺验证/跳步/参数不一致/证据不足
3. **off_track**：误判漏洞类型、在错误页面耗时、或把某一步做错（如未登录就访问受限页面）

标注上建议用统一的 rubric：
- correctness.score：0-1
- severity：缺关键步骤/证据 -> high；小绕路 -> low
- confidence：输入证据越结构化越高

---

## 6) 最小落地建议

- 先做一个 “digest 抽取器”：从题解/构建文件产出 `challenge_digest`，避免把整份构建文件塞进 prompt。
- 再做一个 “trace 标准化器”：把你现在的 `executed_key_actions` 统一到 `run.actions[*]` 的 schema。
- 最后用同一份 `convert_sft_jsonl.py` 输出 messages-only JSONL，保持训练流程不变。
