import openai
import logging
import time
import json
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OpenAIAnalysisError(Exception):
    pass

def analyze_alert_with_openai(alert: Dict[str, Any], config: Dict[str, Any], return_usage: bool = False) -> Dict[str, Any]:
    """
    Analyze a CrowdStrike alert using OpenAI's GPT model with enriched context.
    
    Args:
        alert (Dict[str, Any]): The alert to analyze
        config (Dict[str, Any]): Configuration dictionary
        return_usage (bool): Whether to return token usage statistics
    """
    try:
        openai.api_key = config['openai']['api_key']
        
        # Initialize enrichment modules
        from .mitre_analyzer import MitreAnalyzer
        from .threat_intel import ThreatIntelligence
        
        mitre = MitreAnalyzer()
        threat_intel = ThreatIntelligence(config)
        
        # Get MITRE analysis
        technique_id = alert.get('technique', '').split()[0]  # Extract T#### from technique string
        mitre_analysis = mitre.analyze_technique(technique_id) if technique_id else {}
        
        # Get threat intelligence for IOCs
        intel_data = []
        for indicator in alert.get('indicators', []):
            intel = threat_intel.enrich_ioc(indicator.get('value'), indicator.get('type'))
            if intel:
                intel_data.append({
                    'indicator': indicator.get('value'),
                    'type': indicator.get('type'),
                    'intel': intel
                })
        
        # Prepare the enriched alert context
        alert_context = {
            'hostname': alert.get('hostname', 'Unknown'),
            'severity': alert.get('severity', 'Unknown'),
            'description': alert.get('description', ''),
            'technique': alert.get('technique', ''),
            'timestamp': alert.get('created_time', ''),
            'indicators': alert.get('indicators', []),
            'mitre_context': mitre_analysis,
            'threat_intel': intel_data
        }
        
        # Construct the prompt
        system_prompt = """You are a cybersecurity expert analyzing a security alert. 
        Provide a detailed analysis including:
        1. Risk Assessment
        2. Potential Impact
        3. Root Cause Analysis
        4. Recommended Actions
        5. Similar Attack Patterns (if any)
        Format the response as a structured JSON."""

        user_prompt = f"Analyze this security alert:\n{json.dumps(alert_context, indent=2)}"
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = openai.ChatCompletion.create(
                    model=config['openai']['model'],
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=config['openai']['temperature'],
                    max_tokens=config['openai']['max_tokens']
                )
                
                analysis = response.choices[0].message.content
                return json.loads(analysis)
                
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Retry {attempt + 1}/{max_retries} after error: {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
                
    except Exception as e:
        logger.error(f"OpenAI analysis failed: {str(e)}")
        return {
            "error": str(e),
            "risk_assessment": "Analysis failed",
            "recommended_actions": ["Manual review required due to analysis failure"]
        }