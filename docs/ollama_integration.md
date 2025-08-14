```markdown
# CloudSecVision - Ollama Integration Guide

## Overview

CloudSecVision integrates with Ollama, an open-source platform for running large language models (LLMs) locally. This integration enables AI-powered analysis of security findings without sending data to external cloud services, providing privacy and cost benefits.

## Prerequisites

- Ollama installed on your local machine or accessible server
- Minimum 4GB RAM (8GB+ recommended)
- Stable Internet connection (for initial model download only)
- Linux, macOS, or Windows with WSL

## Installation

### 1. Install Ollama

Visit [Ollama's official website](https://ollama.com/) and follow the installation instructions for your platform:

#### Linux
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

#### macOS
Download the macOS application from the Ollama website.

#### Windows
Install WSL (Windows Subsystem for Linux) and follow the Linux installation instructions.

### 2. Start Ollama Server

```bash
ollama serve
```

This will start the Ollama server on the default port (11434).

## Model Setup

CloudSecVision uses the llama3.2:3b model for security analysis:

```bash
# Pull the model (first-time only, ~2GB download)
ollama pull llama3.2:3b
```

## Configuration

No additional configuration is needed. CloudSecVision automatically connects to the local Ollama server on the default port.

## Usage

When AI analysis is enabled, CloudSecVision will:

1. Collect security findings from scanners
2. Format findings into structured prompts
3. Send prompts to Ollama for processing
4. Parse and format Ollama responses
5. Display results in the dashboard

## Example API Call

```python
import requests
import json

def call_ollama(prompt):
    payload = {
        "model": "llama3.2:3b",
        "prompt": prompt,
        "stream": False
    }
    
    response = requests.post("http://localhost:11434/api/generate", 
                            headers={"Content-Type": "application/json"},
                            data=json.dumps(payload))
    
    if response.status_code == 200:
        return response.json().get("response")
    else:
        return f"Error: {response.status_code}"
```

## Customizing the Model

You can use a different model if preferred:

```bash
# List available models
ollama list

# Pull a different model
ollama pull mistral:7b

# Update CloudSecVision's AI analyzer to use the new model
# Edit analysis/ai_analyzer.py and change the model name
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Ensure Ollama server is running (`ollama serve`)
   - Check that port 11434 is not blocked by firewall

2. **Out of Memory**
   - Try using a smaller model like llama3.2:3b (3 billion parameters)
   - Close other memory-intensive applications

3. **Slow Response Times**
   - First-time model loading may be slow
   - Complex prompts take longer to process
   - Consider hardware acceleration if available

### Diagnostic Commands

```bash
# Check if Ollama server is running
curl http://localhost:11434/api/version

# Verify model is available
ollama list

# Test with a simple prompt
ollama run llama3.2:3b "Hello"
```

## Performance Optimization

- **Batch Processing**: Group related security findings for more efficient analysis
- **Prompt Engineering**: Use concise, well-structured prompts for better results
- **Context Management**: Provide relevant context without overwhelming the model
- **Response Caching**: Common security issues can be cached to avoid redundant processing

## Security Considerations

- **Local Processing**: All data stays on your machine
- **No API Keys**: No external API keys or credentials needed
- **Network Isolation**: Ollama can be run without internet access (after initial model download)
```
