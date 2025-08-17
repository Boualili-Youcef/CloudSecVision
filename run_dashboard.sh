#!/bin/bash

# CloudSecVision Dashboard Launch Script
echo "🛡️ CloudSecVision Dashboard"
echo "=========================="
echo ""

# Check if we're in the project directory
if [[ ! -f "dashboard.py" ]]; then
    echo "❌ Error: dashboard.py not found. Please run this script from the project root directory."
    exit 1
fi

# Virtual environment setup
if [[ ! -d "venv" ]]; then
    echo "⚠️  Virtual environment not found. Creating one..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment already active: $VIRTUAL_ENV"
else
    echo "🔄 Activating virtual environment..."
    source venv/bin/activate
    echo "✅ Virtual environment activated"
fi

# Install dependencies if needed
echo "📦 Checking dependencies..."
if ! python -c "import streamlit" 2>/dev/null; then
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi

echo ""
echo "🚀 Starting Streamlit dashboard..."
echo "📱 Dashboard will be accessible at: http://localhost:8501"
echo ""
echo "⌨️  Press Ctrl+C to stop the server"
echo ""

# Launch Streamlit with options to hide network URLs
./venv/bin/streamlit run dashboard.py \
    --server.port 8501 \
    --server.headless true \
    --server.address localhost \
    --logger.level error \
    --client.showErrorDetails false