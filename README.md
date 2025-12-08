关于渗透Agent（peneration_agent）

在使用conda环境构建requirements.txt文件中对应的环境后，运行main.py即可
注意修改main.py中的内容，以指向不同的漏洞和url目标

渗透Agent项目主要结构：
phase_agent.py - 实现了渗透Agent类，以及Agent的操作类
storage.py - 用异步全局变量（对于每一个线程是一个独立的全局变量）实现了上下文存储
logging_config.py - 实现了logger相关类
config.py - 全局配置文件
mcp_client.py - 实现操作类，并提供一个全局实例用于与mcp服务器交互
mcp_server.py - 实现mcp工具（通过hexstrike-ai提供全套渗透工具）


关于漏洞环境（vulnerables）

对于每一个漏洞，在第一次执行时，需要先执行下面的指令进行镜像构建：
docker compose build --build-arg FLAG="FLAG{d4a5c7e82c7e9c1e935e8d5e35c5a9d2c7b4a3c8f2b5a1d3e7c8a9b2c4d5e6f}" --build-arg flag="FLAG{d4a5c7e82c7e9c1e935e8d5e35c5a9d2c7b4a3c8f2b5a1d3e7c8a9b2c4d5e6f}"

之后只需要执行启动命令即可：
docker compose up

此外有common.mk文件，可以使用它进行所有漏洞环境的总体构建


关于评估Agent（estimate_agent）
--未完成--
