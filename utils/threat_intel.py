import requests
import logging
from typing import Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vt_api_key = config.get('virustotal', {}).get('api_key')
        self.otx_api_key = config.get('alienvault', {}).get('api_key')
        
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Enrich an IOC with threat intelligence data."""
        results = {
            'virustotal': self._check_virustotal(ioc_value, ioc_type),
            'alienvault': self._check_alienvault(ioc_value, ioc_type),
            'first_seen': None,
            'malicious_counts': 0,
            'related_campaigns': []
        }
        
        # Aggregate results
        if results['virustotal'].get('first_seen'):
            results['first_seen'] = results['virustotal']['first_seen']
        results['malicious_counts'] = (
            results['virustotal'].get('malicious_counts', 0) +
            results['alienvault'].get('pulse_count', 0)
        )
        
        return results
    
    def _check_virustotal(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Query VirusTotal for IOC information."""
        if not self.vt_api_key:
            return {}
            
        try:
            base_url = "https://www.virustotal.com/api/v3"
            headers = {"x-apikey": self.vt_api_key}
            
            # Determine endpoint based on IOC type
            if ioc_type == "hash":
                endpoint = f"/files/{ioc_value}"
            elif ioc_type == "domain":
                endpoint = f"/domains/{ioc_value}"
            elif ioc_type == "ip":
                endpoint = f"/ip_addresses/{ioc_value}"
            else:
                return {}
                
            response = requests.get(
                f"{base_url}{endpoint}",
                headers=headers
            )
            response.raise_for_status()
            
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            
            return {
                'first_seen': attributes.get('first_submission_date'),
                'last_seen': attributes.get('last_submission_date'),
                'malicious_counts': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                'reputation': attributes.get('reputation'),
                'tags': attributes.get('tags', [])
            }
            
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed for {ioc_value}: {str(e)}")
            return {}
            
    def _check_alienvault(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Query AlienVault OTX for IOC information."""
        if not self.otx_api_key:
            return {}
            
        try:
            base_url = "https://otx.alienvault.com/api/v1"
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            
            # Determine endpoint based on IOC type
            if ioc_type == "hash":
                endpoint = f"/indicators/file/{ioc_value}/general"
            elif ioc_type == "domain":
                endpoint = f"/indicators/domain/{ioc_value}/general"
            elif ioc_type == "ip":
                endpoint = f"/indicators/IPv4/{ioc_value}/general"
            else:
                return {}
                
            response = requests.get(
                f"{base_url}{endpoint}",
                headers=headers
            )
            response.raise_for_status()
            
            data = response.json()
            
            return {
                'pulse_count': data.get('pulse_info', {}).get('count', 0),
                'adversary': data.get('pulse_info', {}).get('related', {}).get('adversary', []),
                'malware_families': data.get('pulse_info', {}).get('related', {}).get('malware_families', []),
                'industries': data.get('pulse_info', {}).get('related', {}).get('industries', [])
            }
            
        except Exception as e:
            logger.warning(f"AlienVault lookup failed for {ioc_value}: {str(e)}")
            return {}
