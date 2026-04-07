import os
from dotenv import load_dotenv
import re
import glob
import matplotlib
matplotlib.use('Agg') # Set backend to non-interactive
import matplotlib.pyplot as plt
import numpy as np

def parse_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    metrics = {}
    
    # Quantitative
    quant_score = re.search(r'定量得分:\s*([\d\.]+)/10\.0', content)
    if quant_score: metrics['quantitative_score'] = float(quant_score.group(1))
    
    token_usage = re.search(r'总Token使用量:\s*(\d+)', content)
    if token_usage: metrics['total_tokens'] = int(token_usage.group(1))

    time_usage = re.search(r'总用时:\s*([\d\.]+) 秒', content)
    if time_usage: metrics['total_time'] = float(time_usage.group(1))

    req_count = re.search(r'总请求次数:\s*(\d+)', content)
    if req_count: metrics['request_count'] = int(req_count.group(1))
    
    # Qualitative
    qual_metrics = [
        ('task_understanding', r'任务理解能力:\s*([\d\.]+)/10\.0'),
        ('planning_quality', r'方案规划质量:\s*([\d\.]+)/10\.0'),
        ('code_quality', r'代码生成质量:\s*([\d\.]+)/10\.0'),
        ('creativity', r'创造性:\s*([\d\.]+)/10\.0'),
        ('adaptability', r'适应性:\s*([\d\.]+)/10\.0'),
        ('prompt_sensitivity', r'Prompt敏感性:\s*([\d\.]+)/10\.0'),
        ('task_completion', r'任务完成率:\s*([\d\.]+)/10\.0'),
        ('token_efficiency', r'Token使用效率:\s*([\d\.]+)/10\.0')
    ]

    for key, pattern in qual_metrics:
        match = re.search(pattern, content)
        if match:
            metrics[key] = float(match.group(1))
        else:
            metrics[key] = 0.0 # Default to 0 if not found

    return metrics

def main():
    directory = os.path.dirname(os.path.abspath(__file__))
    
    # Explicitly load .env from penetration_agent folder
    env_path = os.path.join(directory, '..', 'penetration_agent', '.env')
    load_dotenv(env_path)
    
    target_model = os.getenv("ESTIMATE_TARGET_MODEL")
    if target_model:
        print(f"Filtering for model: {target_model}")
        files = glob.glob(os.path.join(directory, f'XBEN-*_{target_model}.txt'))
    else:
        files = glob.glob(os.path.join(directory, 'XBEN-*.txt'))
    
    data = []
    model_name = "Unknown"
    
    for filepath in files:
        filename = os.path.basename(filepath)
        # Assuming format {challenge}_{model}.txt
        # Extract challenge code XBEN-XXX-XX
        match = re.match(r'(XBEN-\d{3}-\d{2})_(.+)\.txt', filename)
        if match:
            challenge_code = match.group(1)
            current_model_name = match.group(2)
            model_name = current_model_name # Assume same model for all matching files
            
            file_metrics = parse_file(filepath)
            file_metrics['challenge'] = challenge_code
            data.append(file_metrics)
    
    if not data:
        print("No data found.")
        return

    # Sort data by challenge code
    data.sort(key=lambda x: x['challenge'])
    
    challenges = [d['challenge'] for d in data]
    
    # --- Plotting ---
    plt.figure(figsize=(20, 15))
    plt.suptitle(f'Model Evaluation Performance: {model_name}', fontsize=20)
    
    # 1. Quantitative Score & Task Completion (Bar Chart)
    plt.subplot(2, 2, 1)
    quant_scores = [d.get('quantitative_score', 0) for d in data]
    completion_scores = [d.get('task_completion', 0) for d in data]
    
    x = np.arange(len(challenges))
    width = 0.35
    
    plt.bar(x - width/2, quant_scores, width, label='Quantitative Score', color='skyblue')
    plt.bar(x + width/2, completion_scores, width, label='Task Completion Score', color='orange')
    
    plt.xlabel('Challenge')
    plt.ylabel('Score (0-10)')
    plt.title('Quantitative vs Task Completion Scores')
    plt.xticks(x, challenges, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # 2. Resource Usage (Time & Tokens)
    plt.subplot(2, 2, 2)
    tokens = [d.get('total_tokens', 0) for d in data]
    times = [d.get('total_time', 0) for d in data]
    
    ax1 = plt.gca()
    ax2 = ax1.twinx()
    
    ax1.bar(x, tokens, color='lightgreen', alpha=0.6, label='Total Tokens')
    ax2.plot(x, times, color='red', marker='o', linewidth=2, label='Total Time (s)')
    
    ax1.set_xlabel('Challenge')
    ax1.set_ylabel('Total Tokens', color='green')
    ax2.set_ylabel('Total Time (seconds)', color='red')
    plt.title('Resource Usage: Tokens & Time')
    ax1.set_xticks(x)
    ax1.set_xticklabels(challenges, rotation=45, ha='right')
    
    # Combine legends
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    # 3. Qualitative Metrics Heatmap
    plt.subplot(2, 1, 2)
    
    qual_keys = ['task_understanding', 'planning_quality', 'code_quality', 'creativity', 
                 'adaptability', 'prompt_sensitivity', 'token_efficiency']
    qual_labels = ['Task Understanding', 'Planning', 'Code Gen', 'Creativity', 
                   'Adaptability', 'Prompt Sensitivity', 'Token Efficiency']
    
    heatmap_data = []
    for d in data:
        row = [d.get(k, 0) for k in qual_keys]
        heatmap_data.append(row)
    
    heatmap_data = np.array(heatmap_data).T # Transpose for metrics on Y axis
    
    im = plt.imshow(heatmap_data, cmap='viridis', aspect='auto')
    plt.colorbar(im, label='Score (0-10)')
    
    plt.xticks(np.arange(len(challenges)), challenges, rotation=45, ha='right')
    plt.yticks(np.arange(len(qual_labels)), qual_labels)
    plt.title('Qualitative Metrics Heatmap')
    
    # Add text annotations to heatmap
    for i in range(len(qual_labels)):
        for j in range(len(challenges)):
            text = plt.text(j, i, f'{heatmap_data[i, j]:.1f}',
                           ha="center", va="center", color="w" if heatmap_data[i, j] < 7 else "black")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    if target_model:
        output_filename = f'model_performance_analysis_{target_model}.png'
    else:
        output_filename = 'model_performance_analysis.png'
        
    output_path = os.path.join(directory, output_filename)
    plt.savefig(output_path)
    print(f"Chart saved to: {output_path}")

if __name__ == "__main__":
    main()
