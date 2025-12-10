## 简介：
- 本项目实现了一个Benchmark Agent，与hexstrike-ai提供的渗透工具集成，用于对指定渗透系统进行攻击能力评估。
- 操作系统：Ubuntu 20.04（windows wsl）
- Python 3.10

## 快速开始

1. 创建并激活 conda 环境（基于项目根目录下的 requirements.txt）：
```bash
conda create -n ea_env python=3.10 -y
conda activate ea_env
pip install -r requirements.txt
```

2. 启动 hexstrike-ai 渗透工具代理（在项目根目录）：
```bash
python hexstrike_server.py
```

3. 编辑 `main.py`，根据需要指向不同的漏洞与目标 URL，然后运行：
```bash
python main.py
```

## 漏洞环境（vulnerables）构建与启动

- 第一次使用某个漏洞镜像时需构建镜像（示例包含 FLAG 参数）：
```bash
docker compose build --build-arg FLAG="FLAG{...}" --build-arg flag="FLAG{...}"
```

- 构建完成后启动服务：
```bash
docker compose up
```

- 项目目录下有 `common.mk`，可用于一键构建/管理所有漏洞环境。

## 渗透Agent（penetration_agent）

## 渗透Agent结构
- phase_agent.py — 实现渗透 Agent 类及其操作。
- storage.py — 基于异步全局变量（线程级独立）实现上下文存储。
- logging_config.py — 日志相关配置与工具。
- config.py — 全局配置项。
- mcp_client.py — 操作客户端实现，并提供与 mcp 服务器交互的全局实例。
- mcp_server.py — 封装 mcp 工具（依赖 hexstrike-ai 提供的工具集）。
- main.py — 启动脚本，配置目标并运行 Agent。

## 评估 Agent（estimate_agent）
- 功能尚未完成（待实现评估策略与打分机制）。
