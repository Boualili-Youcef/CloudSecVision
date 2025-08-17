#!/bin/bash

echo "🐳 Building CloudSecVision Docker Images"
echo "========================================"

# Build of the main application
echo "📦 Building main application..."
docker build -t cloudsecvision:latest .

# Build of the documentation
echo "📚 Building documentation..."
cd website && docker build -t cloudsecvision-docs:latest .

echo "✅ Build completed successfully!"
echo ""
echo "🚀 To start the application:"
echo "   docker-compose up -d"
echo ""
echo "📱 Access points:"
echo "   - Dashboard: http://localhost:8501"
echo "   - Documentation: http://localhost:3000"
echo "   - Ollama API: http://localhost:11434"