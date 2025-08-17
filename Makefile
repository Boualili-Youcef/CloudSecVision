.PHONY: help build run stop logs clean

help: ## Show help
	@echo "🐳 CloudSecVision Docker Commands"
	@echo "================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build Docker image (main app only)
	@echo "🔨 Building main Docker image..."
	@docker build -t cloudsecvision:latest .
	@echo "✅ Main image built successfully!"

run: ## Start the application
	@echo "🚀 Starting CloudSecVision..."
	@docker run -d \
        -p 8501:8501 \
        -v ~/.aws:/home/cloudsec/.aws:ro \
        -e AWS_PROFILE=default \
        --name cloudsecvision-app \
        cloudsecvision:latest
	@echo "✅ Application started!"
	@echo "📱 Dashboard: http://localhost:8501"

run-env: ## Start with environment variables
	@echo "🚀 Starting CloudSecVision with env vars..."
	@docker run -d \
        -p 8501:8501 \
        -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
        -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
        -e AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1} \
        --name cloudsecvision-app \
        cloudsecvision:latest
	@echo "✅ Application started!"
	@echo "📱 Dashboard: http://localhost:8501"

run-compose: ## Start with docker-compose
	@echo "🚀 Starting CloudSecVision with compose..."
	@docker-compose up -d cloudsecvision
	@echo "✅ Application started!"
	@echo "📱 Dashboard: http://localhost:8501"

stop: ## Stop the application
	@echo "🛑 Stopping CloudSecVision..."
	@docker stop cloudsecvision-app || true
	@docker rm cloudsecvision-app || true
	@echo "✅ Application stopped!"

logs: ## View the logs
	@docker logs -f cloudsecvision-app

clean: ## Clean up images and volumes
	@echo "🧹 Cleaning up..."
	@docker stop cloudsecvision-app || true
	@docker rm cloudsecvision-app || true
	@docker rmi cloudsecvision:latest || true
	@docker system prune -f
	@echo "✅ Cleanup completed!"

health: ## Check the health of the service
	@docker ps | grep cloudsecvision-app || echo "❌ Container not running"
	@echo ""
	@curl -s http://localhost:8501 > /dev/null && echo "✅ Dashboard is healthy" || echo "❌ Dashboard not responding"

shell: ## Access container shell
	@docker exec -it cloudsecvision-app /bin/bash

restart: ## Restart the application
	@make stop
	@make run

test-aws: ## Test AWS credentials in container
	@echo "🧪 Testing AWS credentials..."
	@docker run --rm \
        -v ~/.aws:/home/cloudsec/.aws:ro \
        -e AWS_PROFILE=default \
        cloudsecvision:latest \
        python -c "import boto3; print('✅ AWS credentials OK'); print('Region:', boto3.Session().region_name)"

# Ajouter ces nouvelles commandes à votre Makefile existant

build-docs: ## Build documentation Docker image
	@echo "📚 Building documentation image..."
	@cd website && docker build -t cloudsecvision-docs:latest .
	@echo "✅ Documentation image built successfully!"

run-docs: ## Start documentation server
	@echo "📚 Starting documentation server..."
	@docker run -d \
        -p 3000:3000 \
        --name cloudsecvision-docs \
        cloudsecvision-docs:latest
	@echo "✅ Documentation started!"
	@echo "📚 Documentation: http://localhost:3000/cloudsecvision/"

stop-docs: ## Stop documentation server
	@echo "📚 Stopping documentation..."
	@docker stop cloudsecvision-docs || true
	@docker rm cloudsecvision-docs || true
	@echo "✅ Documentation stopped!"

docs-logs: ## View documentation logs
	@docker logs -f cloudsecvision-docs

# Commandes Ollama/LLM
run-ollama: ## Start Ollama LLM server
	@echo "🤖 Starting Ollama LLM server..."
	@docker run -d \
        -p 11434:11434 \
        -v ollama_data:/root/.ollama \
        --name cloudsecvision-ollama \
        ollama/ollama:latest
	@echo "✅ Ollama started!"
	@echo "🤖 Ollama API: http://localhost:11434"

stop-ollama: ## Stop Ollama LLM server
	@echo "🤖 Stopping Ollama..."
	@docker stop cloudsecvision-ollama || true
	@docker rm cloudsecvision-ollama || true
	@echo "✅ Ollama stopped!"

ollama-logs: ## View Ollama logs
	@docker logs -f cloudsecvision-ollama

install-model: ## Install a model in Ollama (default: llama2)
	@echo "🤖 Installing model in Ollama..."
	@docker exec cloudsecvision-ollama ollama pull ${MODEL:-llama2}
	@echo "✅ Model ${MODEL:-llama2} installed!"

list-models: ## List installed models in Ollama
	@echo "🤖 Listing installed models..."
	@docker exec cloudsecvision-ollama ollama list

test-llm: ## Test LLM with a simple prompt
	@echo "🧪 Testing LLM..."
	@curl -s http://localhost:11434/api/generate -d '{"model":"llama2","prompt":"Hello, how are you?","stream":false}' | jq -r '.response' || echo "❌ LLM not responding or jq not installed"

test-llm-security: ## Test LLM with security analysis
	@echo "🧪 Testing LLM for security analysis..."
	@curl -s http://localhost:11434/api/generate -d '{"model":"llama2","prompt":"Analyze this security issue: SSH port 22 open to 0.0.0.0/0","stream":false}' | jq -r '.response' || echo "❌ LLM not responding"

# Commandes combinées
run-all: ## Start app, docs and Ollama
	@make run
	@make run-docs
	@make run-ollama
	@echo ""
	@echo "🎉 All services started!"
	@echo "📱 Dashboard: http://localhost:8501"
	@echo "📚 Documentation: http://localhost:3000/cloudsecvision/"
	@echo "🤖 Ollama API: http://localhost:11434"

stop-all: ## Stop all services
	@make stop
	@make stop-docs
	@make stop-ollama
	@echo "✅ All services stopped!"

status: ## Show status of all services
	@echo "🔍 Service Status:"
	@echo "=================="
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep cloudsecvision || echo "No CloudSecVision containers running"
	@echo ""
	@echo "🌐 Service URLs:"
	@echo "📱 Dashboard: http://localhost:8501"
	@echo "📚 Documentation: http://localhost:3000/cloudsecvision/"
	@echo "🤖 Ollama API: http://localhost:11434"

# Debugging et développement
debug-app: ## Run app in interactive mode for debugging
	@echo "🐛 Starting app in debug mode..."
	@docker run -it --rm \
        -p 8501:8501 \
        -v ~/.aws:/home/cloudsec/.aws:ro \
        -v $(PWD):/home/cloudsec/app \
        --name cloudsecvision-debug \
        cloudsecvision:latest \
        /bin/bash

shell-ollama: ## Access Ollama container shell
	@docker exec -it cloudsecvision-ollama /bin/bash