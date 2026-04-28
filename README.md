# LLMPenEval：Penetration Testing Capability Evaluation Method Based on Domain Fine-tuned Model

## Project Overview

This project evaluates the penetration capabilities of large language models and agents in real vulnerable environments, using fine-tuned models as the benchmark target.

> Related evaluation outputs are stored under the `eval_reports` folder, while penetration logs are stored in multiple folders under `estimate_agent` that are named after the LLM and the target challenge.

The typical execution flow is:

1. Use `penetration_agent` to invoke the Claude Code toolchain and perform penetration testing against the target challenge.
2. Collect execution logs and events to generate structured outputs.
3. Use `estimate_agent` to perform quantitative and qualitative evaluation of the attack process and results, then generate reports and charts.

This project is intended for security research and benchmarking only. Do not use it against unauthorized targets.

## Environment

- OS: Ubuntu 20.04, preferably running under WSL2 Ubuntu
- Python: 3.10
- Docker / Docker Compose: used to start vulnerable environments

## Repository Layout

- `penetration_agent/`: penetration execution agent, including attack flow and tool calls
- `estimate_agent/`: evaluation agent for scoring, reporting, and training-data generation
- `vulnerables/`: vulnerable challenge environments and orchestration files
- `hexstrike-ai/`: server-side implementation of the penetration toolchain
- `eval_results/`: raw execution results and log archives
- `eval_inputs/`: intermediate artifacts used for evaluation
- `eval_reports/`: evaluation reports and visualization outputs

## Quick Start

### 1) Install Dependencies

Run the following in the repository root:

```bash
conda create -n es_agent python=3.10 -y
conda activate es_agent
pip install -r requirements.txt
```

Optional system tools:

```bash
sudo apt update
sudo apt install -y whatweb
```

### 2) Start the hexstrike Tool Server

```bash
python hexstrike-ai/hexstrike_server.py
```

Keep this service running in a separate terminal.

### 3) Start the Vulnerable Environment

Enter the specific challenge directory and run the following commands. The first run requires a build step:

```bash
docker compose build --build-arg FLAG="FLAG{xben058-testflag}" --build-arg flag="FLAG{xben058-testflag}"
docker compose up -d
docker ps -a
```

Notes:
- `docker ps -a` shows containers and port mappings. Access the mapped host port, not the internal container port.
- `vulnerables/common.mk` can be used to manage multiple vulnerable environments in a unified way.

### 4) Run the Penetration Agent

First edit `penetration_agent/main.py` to point to the desired challenge, IP, and port, then run:

```bash
cd penetration_agent
python main.py
```

### 5) Run the Evaluation Agent

Return to the repository root and run:

```bash
python -m estimate_agent.evaluator
```

### 6) Generate Evaluation Charts

```bash
python eval_reports/visualize_reports.py -d eval_reports
python eval_reports/visualize_all_models.py -d eval_reports
```

## Training Data Generation (Optional)

If you need additional evaluation or training data:

Single-challenge generation:

```bash
python -m estimate_agent.build_data_new \
	--challenge-id XBEN-015-24 \
	--output-dir estimate_agent/generated_critic_data \
	--env-root vulnerables/benchmark_envs \
	--num-negatives-per-step 2
```

Batch-range generation:

```bash
python -m estimate_agent.build_data_new \
	--challenge-range XBEN-061-24 XBEN-099-24 \
	--output-dir estimate_agent/generated_critic_data
```

Merge and convert to SFT training format:

```bash
python -m estimate_agent.convert_sft_jsonl \
	--input estimate_agent/generated_critic_data \
	--pattern "*_critic_samples.jsonl" \
	--output estimate_agent/generated_critic_data/sft_train_merged.jsonl \
	--deduplicate
```

## Module Summary

### penetration_agent

Key files:

- `phase_agents.py`: penetration phase management and single-agent execution flow
- `mcp_server.py`: wrapper that exposes callable tools
- `mcp_client.py`: MCP client and service interaction layer
- `storage.py`: context and state storage
- `logging_config.py`: logging utilities and configuration
- `config.py`: global configuration
- `main.py`: entry point

### estimate_agent

Key files:

- `evaluator.py`: main entry point for evaluation
- `evaluation_algorithm.py`: scoring algorithm
- `evaluation_agent.py`: evaluation workflow orchestration
- `build_data_new.py`: sample generation
- `convert_sft_jsonl.py`: data conversion

## Output Artifacts

- `eval_results/`: raw execution results such as events, compact summaries, and step traces
- `eval_inputs/<model_name>/`: normalized inputs used for evaluation
- `eval_reports/<model_name>/`: text evaluation reports
- `eval_reports/charts/<model_name>/`: model-level charts

## FAQ

1. `python -m estimate_agent.evaluator` exits early or produces no output
   - Check whether the hexstrike service is running.
   - Check whether the target container started correctly and whether the port is reachable.

2. Docker is running but the vulnerable service cannot be reached
   - Use `docker ps -a` to verify the port mapping.
   - Make sure you are accessing the host port rather than the container's internal port.

3. Dependency installation fails
   - Make sure Python 3.10 is being used.
   - It is recommended to create a fresh conda environment and reinstall `requirements.txt`.

## Compliance and Security

This project is intended only for authorized security testing, education, and research. Do not use it against unauthorized targets.