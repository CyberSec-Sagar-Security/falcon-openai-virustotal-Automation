import requests
import logging
from typing import Dict, Any, List
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class MitreAnalyzer:
    def __init__(self):
        self.mitre_data = self._load_mitre_data()
        
    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK Enterprise framework data."""
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            return {}
            
    def analyze_technique(self, technique_id: str) -> Dict[str, Any]:
        """Analyze a MITRE ATT&CK technique and provide context."""
        try:
            # Find the technique in MITRE data
            technique = next(
                (obj for obj in self.mitre_data.get('objects', [])
                 if obj.get('type') == 'attack-pattern' and
                 obj.get('external_references', [{}])[0].get('external_id') == technique_id),
                None
            )
            
            if not technique:
                return {
                    'error': f'Technique {technique_id} not found',
                    'success': False
                }
                
            # Extract relevant information
            return {
                'success': True,
                'technique_id': technique_id,
                'name': technique.get('name'),
                'description': technique.get('description'),
                'platforms': technique.get('x_mitre_platforms', []),
                'permissions_required': technique.get('x_mitre_permissions_required', []),
                'detection': technique.get('x_mitre_detection', ''),
                'mitigation': self._find_mitigations(technique_id),
                'related_techniques': self._find_related_techniques(technique_id),
                'typical_severity': self._assess_technique_severity(technique)
            }
        except Exception as e:
            logger.error(f"Error analyzing technique {technique_id}: {e}")
            return {'error': str(e), 'success': False}
    
    def _find_mitigations(self, technique_id: str) -> List[str]:
        """Find mitigations for a specific technique."""
        mitigations = []
        try:
            for obj in self.mitre_data.get('objects', []):
                if obj.get('type') == 'course-of-action' and \
                   any(ref.get('source_name') == 'mitre-attack' and 
                       technique_id in ref.get('external_id', '') 
                       for ref in obj.get('external_references', [])):
                    mitigations.append({
                        'name': obj.get('name'),
                        'description': obj.get('description')
                    })
            return mitigations
        except Exception as e:
            logger.error(f"Error finding mitigations: {e}")
            return []
    
    def _find_related_techniques(self, technique_id: str) -> List[str]:
        """Find techniques that are commonly used together."""
        related = []
        try:
            for obj in self.mitre_data.get('objects', []):
                if obj.get('type') == 'relationship' and \
                   (obj.get('source_ref', '').startswith('attack-pattern') or \
                    obj.get('target_ref', '').startswith('attack-pattern')):
                    # Check if our technique is involved in this relationship
                    if technique_id in obj.get('source_ref', '') or \
                       technique_id in obj.get('target_ref', ''):
                        related.append(obj.get('source_ref', '')
                                    if technique_id in obj.get('target_ref', '')
                                    else obj.get('target_ref', ''))
            return list(set(related))[:5]  # Return top 5 related techniques
        except Exception as e:
            logger.error(f"Error finding related techniques: {e}")
            return []
    
    def _assess_technique_severity(self, technique: Dict) -> str:
        """Assess the typical severity of a technique based on its attributes."""
        severity = "medium"  # Default severity
        
        # Check for high-severity indicators
        high_severity_keywords = [
            "privilege escalation", "credential access", "defense evasion",
            "persistence", "lateral movement"
        ]
        
        if any(keyword in technique.get('name', '').lower() 
               for keyword in high_severity_keywords):
            severity = "high"
            
        if "admin" in str(technique.get('x_mitre_permissions_required', [])).lower():
            severity = "critical"
            
        return severity
