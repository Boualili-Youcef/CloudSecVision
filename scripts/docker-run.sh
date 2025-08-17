#!/bin/bash
# scripts/docker-run.sh

echo "🚀 Starting CloudSecVision with Docker Compose"
echo "=============================================="

# Verify that Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Verify that Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create the .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
# AWS Configuration
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here

# Application Configuration
PORT=8501
ENVIRONMENT=production
EOF
    echo "⚠️ Please edit .env file with your AWS credentials"
fi

# Start the services
echo "🐳 Starting services..."
docker-compose up -d

echo "✅ Services started successfully!"
echo ""
echo "📱 Access your application:"
echo "   🛡️  Dashboard: http://localhost:8501"
echo "   📚 Documentation: http://localhost:3000"
echo "   🤖 Ollama API: http://localhost:11434"
echo ""
echo "📊 Check status: docker-compose ps"
echo "📋 View logs: docker-compose logs -f"
echo "🛑 Stop services: docker-compose down"