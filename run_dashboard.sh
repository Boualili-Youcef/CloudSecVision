#!/bin/bash

# CloudSecVision Dashboard Launch Script
echo "🛡️ CloudSecVision Dashboard"
echo "=========================="
echo ""

# Virtual environment check
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment detected: $VIRTUAL_ENV"
else
    echo "⚠️  No virtual environment detected"
    echo "💡 Recommendation: activate your venv with 'source venv/bin/activate'"
fi

echo ""
echo "🚀 Starting Streamlit dashboard..."
echo "📱 Dashboard will be accessible at: http://localhost:8501"
echo ""
echo "⌨️  Press Ctrl+C to stop the server"
echo ""

# Launch Streamlit
streamlit run dashboard.py --server.port 8501 --server.headless true
