import json
import requests
from datetime import datetime

def analyze_security_issues(scan_results):
    """Analyse the security issues found with Ollama AI"""
    
    print("🤖 Starting AI analysis...")
    
    total_issues = 0
    for service_issues in scan_results.values():
        if isinstance(service_issues, list):
            total_issues += len(service_issues)
    
    if total_issues == 0:
        return {
            "message": "✅ No security issues found!",
            "risk_score": 0,
            "recommendations": ["Continue monitoring your AWS infrastructure"]
        }
    
    prompt = f"""
        Analyze these AWS security vulnerabilities and provide recommendations.

        Data: {json.dumps(scan_results, indent=2)}

        Please respond with a JSON object containing EXACTLY these fields:
        {{
            "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
            "risk_score": a number from 0 to 100,
            "top_priorities": ["action1", "action2", "action3"],
            "recommendations": ["rec1", "rec2", "rec3"]
        }}

        Only return the JSON object, nothing else.
        """
    
    try:
        print("📡 Sending request to Ollama...")
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': 'llama3.2:3b',
                'prompt': prompt,
                'stream': False
            },
            timeout=120
        )
        
        print(f"📊 Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            ai_text = result.get('response', '')
            
            print(f"🤖 AI Response received (length: {len(ai_text)})")
            print(f"📝 First 200 chars: {ai_text[:200]}...")
            
            if not ai_text.strip():
                print("❌ Empty response from Ollama")
                return get_fallback_analysis(total_issues)
            
            try:
                # Try to extract JSON from the response
                start_idx = ai_text.find('{')
                end_idx = ai_text.rfind('}') + 1
                if start_idx != -1 and end_idx != -1:
                    json_str = ai_text[start_idx:end_idx]
                    print(f"🔍 Extracted JSON: {json_str[:200]}...")
                    ai_analysis = json.loads(json_str)
                    
                    # Validate the required fields and provide defaults if missing
                    validated_analysis = {
                        "severity": ai_analysis.get('severity', 'HIGH'),
                        "risk_score": ai_analysis.get('risk_score', min(total_issues * 20, 100)),
                        "total_issues": total_issues,
                        "top_priorities": ai_analysis.get('top_priorities', [
                            "Review and restrict public access",
                            "Implement principle of least privilege",
                            "Enable security monitoring"
                        ]),
                        "recommendations": ai_analysis.get('recommendations', [
                            "Configure restrictive security groups",
                            "Review IAM policies for over-permissions",
                            "Enable AWS CloudTrail for auditing"
                        ])
                    }
                    
                    print("✅ Successfully parsed and validated AI response")
                    return validated_analysis
                else:
                    print("⚠️ No JSON found in AI response")
                    print(f"Full response: {ai_text}")
            except json.JSONDecodeError as e:
                print(f"⚠️ Failed to parse JSON: {e}")
                print(f"Attempted to parse: {json_str if 'json_str' in locals() else 'N/A'}")
        else:
            print(f"❌ HTTP Error {response.status_code}")
            print(f"Response text: {response.text}")
    
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {e}")
        print("💡 Make sure Ollama is running with: ollama serve")
    except requests.exceptions.Timeout as e:
        print(f"❌ Request timeout: {e}")
    except Exception as e:
        print(f"⚠️ AI analysis failed: {e}")
        import traceback
        print("🔍 Full traceback:")
        traceback.print_exc()
    
    print("🔄 Using fallback analysis...")
    return get_fallback_analysis(total_issues)

def get_fallback_analysis(total_issues):
    """Generate fallback analysis when AI is not available"""
    return {
        "severity": "HIGH" if total_issues > 3 else "MEDIUM",
        "risk_score": min(total_issues * 20, 100),
        "total_issues": total_issues,
        "top_priorities": [
            "Review and restrict public access",
            "Implement principle of least privilege",
            "Enable security monitoring"
        ],
        "recommendations": [
            "Configure restrictive security groups",
            "Review IAM policies for over-permissions",
            "Enable AWS CloudTrail for auditing",
            "Set up automated security scanning"
        ]
    }

def display_ai_analysis(analysis):
    """Display the AI analysis results in a user-friendly format"""
    
    print("\n" + "="*50)
    print("🤖 AI SECURITY ANALYSIS")
    print("="*50)
    
    if analysis is None:
        print("❌ No analysis data available")
        return
    
    print(f"📊 Total Issues Found: {analysis.get('total_issues', 0)}")
    print(f"⚠️  Severity Level: {analysis.get('severity', 'UNKNOWN')}")
    print(f"🎯 Risk Score: {analysis.get('risk_score', 0)}/100")
    
    priorities = analysis.get('top_priorities', [])
    if priorities:
        print(f"\n🚨 TOP PRIORITIES:")
        for priority in priorities:
            print(f"   • {priority}")
    else:
        print(f"\n🚨 TOP PRIORITIES: None available")
    
    recommendations = analysis.get('recommendations', [])
    if recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in recommendations:
            print(f"   • {rec}")
    else:
        print(f"\n💡 RECOMMENDATIONS: None available")
    
    print("="*50)