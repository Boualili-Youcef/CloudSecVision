import json
import requests
import traceback
from datetime import datetime

def generate_iam_report(iam_results):
    """Generate a comprehensive IAM security report using Ollama AI"""
    
    print("🤖 Generating IAM security report with AI...")
    
    if not iam_results or len(iam_results) == 0:
        return {
            "summary": "✅ No IAM security issues detected. Your IAM policies appear to follow the principle of least privilege.",
            "risk_assessment": "LOW",
            "detailed_analysis": "All scanned IAM policies are properly configured without overly permissive access patterns.",
            "recommendations": [
                "Continue regular IAM policy reviews",
                "Consider implementing IAM Access Analyzer for ongoing monitoring",
                "Maintain documentation of IAM policy purposes"
            ],
            "priority_actions": [],
            "compliance_status": "COMPLIANT"
        }

    prompt = f"""
    Analyze these IAM security issues and provide a comprehensive security report.
    
    IAM Issues Found: {json.dumps(iam_results, indent=2)}
    
    Please provide a detailed security analysis in JSON format with these exact fields:
    {{
        "summary": "Brief executive summary of IAM security posture",
        "risk_assessment": "CRITICAL/HIGH/MEDIUM/LOW",
        "detailed_analysis": "Detailed technical analysis of the security issues",
        "recommendations": ["specific actionable recommendations"],
        "priority_actions": ["immediate actions needed"],
        "compliance_status": "NON_COMPLIANT/PARTIALLY_COMPLIANT/COMPLIANT"
    }}
    
    Focus on:
    - Impact of overly permissive policies
    - Potential attack vectors
    - Compliance implications
    - Specific remediation steps
    
    Only return the JSON object, nothing else.
    """

    try:
        print("📡 Sending IAM analysis request to Ollama...")
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': 'llama3.2:3b',
                'prompt': prompt,
                'stream': False
            },
            timeout=10000
        )

        if response.status_code == 200:
            result = response.json()
            ai_text = result.get('response', '')

            print(f"🤖 AI Response received for IAM analysis")

            if ai_text.strip():
                try:
                    start_idx = ai_text.find('{')
                    end_idx = ai_text.rfind('}') + 1
                    if start_idx != -1 and end_idx != -1:
                        json_str = ai_text[start_idx:end_idx]
                        return json.loads(json_str)
                    else:
                        print("⚠️ No JSON found in AI response")
                except json.JSONDecodeError as e:
                    print(f"⚠️ Failed to parse IAM analysis JSON: {e}")
        else:
            print(f"❌ HTTP Error {response.status_code}")

    except requests.exceptions.ConnectionError:
        print("❌ Connection error: Make sure Ollama is running")
    except Exception as e:
        print(f"⚠️ IAM AI analysis failed: {e}")

    # Fallback analysis
    return {
        "summary": f"⚠️ {len(iam_results)} IAM security issues detected requiring attention.",
        "risk_assessment": "HIGH" if len(iam_results) > 5 else "MEDIUM",
        "detailed_analysis": "Multiple IAM policies contain overly permissive configurations that violate the principle of least privilege.",
        "recommendations": [
            "Review and restrict overly permissive IAM policies",
            "Implement specific resource-based permissions",
            "Remove wildcard (*) permissions where possible",
            "Conduct regular IAM policy audits"
        ],
        "priority_actions": [
            "Immediately review policies with wildcard permissions",
            "Document business justification for broad permissions",
            "Implement least privilege access controls"
        ],
        "compliance_status": "NON_COMPLIANT"
    }

def analyze_security_issues(scan_results):
    """Analyse the security issues found with Ollama AI.

    Accepts either:
    - A dict mapping service names to lists of issue objects, e.g. {"s3": [{...}, ...]}
    - A raw list of issue objects (e.g., the S3 report array). In this case, it will be
      normalized to {"s3": <list>}.
    """

    print("🤖 Starting AI analysis...")

    # Normalize input: allow a raw list of findings (e.g., S3-only JSON array)
    if isinstance(scan_results, list):
        scan_results = {"s3": scan_results}
    elif not isinstance(scan_results, dict):
        # Unknown format; coerce to an empty dict to avoid crashes
        print("⚠️ Unsupported scan_results type, expected dict or list. Proceeding with empty data.")
        scan_results = {}

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
            timeout=10000
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