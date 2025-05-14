import logging
from typing import Dict, Any, List
import requests
import json
from datetime import datetime
import os
import subprocess

logger = logging.getLogger(__name__)

class ResponseAutomation:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.falcon_config = config.get('crowdstrike', {})
        self.automation_config = config.get('response_automation', {})
        
    def evaluate_and_respond(self, alert: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate alert and analysis to determine and execute response actions."""
        response_actions = []
        try:
            # Check if automation is enabled
            if not self.automation_config.get('enabled', False):
                logger.info("Response automation is disabled")
                return {'status': 'disabled'}

            severity = alert.get('severity', 'low').lower()
            auto_isolate_threshold = self.automation_config.get('auto_isolate_threshold', 'critical').lower()
            
            # Determine necessary actions
            actions_needed = self._determine_actions(severity, alert, analysis)
            
            # Execute actions
            for action in actions_needed:
                if action == 'isolate_host' and severity == auto_isolate_threshold:
                    result = self._isolate_host(alert['device_id'])
                    response_actions.append({
                        'action': 'isolate_host',
                        'status': result.get('status', 'failed'),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                elif action == 'collect_evidence':
                    evidence = self._collect_evidence(alert)
                    response_actions.append({
                        'action': 'collect_evidence',
                        'status': 'completed',
                        'evidence_path': evidence.get('path'),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            return {
                'status': 'completed',
                'actions_taken': response_actions
            }
            
        except Exception as e:
            logger.error(f"Error in response automation: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'actions_taken': response_actions
            }
    
    def _determine_actions(self, severity: str, alert: Dict[str, Any], 
                         analysis: Dict[str, Any]) -> List[str]:
        """Determine which response actions should be taken."""
        actions = []
        allowed_actions = self.automation_config.get('allowed_actions', [])
        
        # Check for host isolation criteria
        if ('isolate_host' in allowed_actions and
            severity in ['critical', 'high'] and
            analysis.get('risk_assessment', '').lower() in ['critical', 'high']):
            actions.append('isolate_host')
        
        # Check for evidence collection criteria
        if 'collect_evidence' in allowed_actions:
            if severity != 'low' or 'lateral_movement' in str(analysis).lower():
                actions.append('collect_evidence')
        
        return actions
    
    def _isolate_host(self, device_id: str) -> Dict[str, Any]:
        """Isolate a host using CrowdStrike API."""
        try:
            # Get authentication token
            auth_url = f"{self.falcon_config['base_url']}/oauth2/token"
            auth_response = requests.post(
                auth_url,
                data={
                    'client_id': self.falcon_config['client_id'],
                    'client_secret': self.falcon_config['client_secret']
                }
            )
            auth_response.raise_for_status()
            token = auth_response.json()['access_token']
            
            # Isolate the host
            isolate_url = f"{self.falcon_config['base_url']}/devices/entities/devices-actions/v2"
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            data = {
                'action_name': 'contain',
                'device_ids': [device_id]
            }
            
            response = requests.post(isolate_url, headers=headers, json=data)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'response': response.json()
            }
            
        except Exception as e:
            logger.error(f"Failed to isolate host {device_id}: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _collect_evidence(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence from the affected system."""
        try:
            # Create evidence directory
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            evidence_dir = os.path.join('evidence', f"incident_{timestamp}")
            os.makedirs(evidence_dir, exist_ok=True)
            
            # Save alert details
            alert_file = os.path.join(evidence_dir, 'alert_details.json')
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
            
            # If we have local access to the system, collect additional evidence
            if self._has_local_access(alert.get('hostname')):
                self._collect_local_evidence(alert.get('hostname'), evidence_dir)
            
            return {
                'status': 'success',
                'path': evidence_dir
            }
            
        except Exception as e:
            logger.error(f"Failed to collect evidence: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _has_local_access(self, hostname: str) -> bool:
        """Check if we have local access to the system."""
        try:
            result = subprocess.run(['ping', '-n', '1', hostname], 
                                 capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _collect_local_evidence(self, hostname: str, evidence_dir: str):
        """Collect evidence from a system we have local access to."""
        try:
            # Define evidence collection commands
            commands = [
                'tasklist /v',
                'netstat -ano',
                'wmic startup list full',
                'reg query "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"'
            ]
            
            # Execute commands and save output
            for cmd in commands:
                try:
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    filename = f"{cmd.split()[0]}.txt".replace('/', '_')
                    with open(os.path.join(evidence_dir, filename), 'w') as f:
                        f.write(output)
                except Exception as e:
                    logger.warning(f"Failed to run command {cmd}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to collect local evidence: {e}")
            raise
