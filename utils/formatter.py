import json
from datetime import datetime
from typing import Dict, Any

def generate_summary_report(alert: Dict[str, Any], enriched_result: Dict[str, Any]) -> str:
    """Generate a formatted Teams message from the alert and OpenAI analysis."""
    
    # Convert timestamp to readable format
    timestamp = alert.get('created_time', '')
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        formatted_time = dt.strftime('%d-%b-%Y %I:%M%p')
    except:
        formatted_time = timestamp

    # Extract key information
    hostname = alert.get('hostname', 'Unknown')
    severity = alert.get('severity', 'Unknown').upper()
    
    # Get analysis details
    risk_assessment = enriched_result.get('risk_assessment', 'N/A')
    recommended_actions = enriched_result.get('recommended_actions', [])
    potential_impact = enriched_result.get('potential_impact', 'N/A')
    root_cause = enriched_result.get('root_cause_analysis', 'N/A')
    
    # Format recommended actions as bullet points
    action_items = '\n'.join([f"  - {action}" for action in recommended_actions])
    
    # Add MITRE ATT&CK context if available
    mitre_info = ""
    if alert.get('mitre_context'):
        mitre = alert['mitre_context']
        mitre_info = f"""
MITRE ATT&CK:
- Technique: {mitre.get('technique_id', 'N/A')} - {mitre.get('name', 'Unknown')}
- Tactics: {', '.join(mitre.get('tactics', ['N/A']))}
"""

    # Create message format
    message = f"""
CrowdStrike Alert: {alert.get('description', 'Alert Details Not Available')}

Host: {hostname}
Severity: {severity}
Timestamp: {formatted_time}
{mitre_info}

Analysis:
---------
Risk Assessment:
{risk_assessment}

Root Cause:
{root_cause}

Potential Impact:
{potential_impact}

Recommended Actions:
{action_items}

Alert Details:
-------------
- Technique: {alert.get('technique', 'N/A')}
- Alert ID: {alert.get('id', 'N/A')}

---
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
Links: [Full Report](#) | [Alert Dashboard](#) | [Incident Timeline](#)
"""

    return message