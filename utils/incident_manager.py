import logging
from typing import Dict, Any
from jira import JIRA
from datetime import datetime

logger = logging.getLogger(__name__)

class IncidentManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._init_jira()
        
    def _init_jira(self):
        """Initialize Jira connection."""
        jira_config = self.config.get('jira', {})
        try:
            self.jira = JIRA(
                server=jira_config.get('server_url'),
                basic_auth=(
                    jira_config.get('username'),
                    jira_config.get('api_token')
                )
            )
            self.project_key = jira_config.get('project_key')
            self.issue_type = jira_config.get('issue_type', 'Security')
            logger.info("Successfully connected to Jira")
        except Exception as e:
            logger.error(f"Failed to initialize Jira: {str(e)}")
            self.jira = None
            
    def create_incident_ticket(self, alert: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Create a Jira incident ticket from an alert and its analysis."""
        if not self.jira:
            logger.error("Jira not initialized")
            return None
            
        try:
            # Prepare ticket fields
            summary = f"Security Incident: {alert.get('description', 'Unknown Alert')}"
            
            description = f"""
h2. Security Incident Details

*Host:* {alert.get('hostname', 'Unknown')}
*Severity:* {alert.get('severity', 'Unknown')}
*Detection Time:* {alert.get('created_time', 'Unknown')}
*Technique:* {alert.get('technique', 'Unknown')}

h2. AI Analysis Summary
*Risk Assessment:* {analysis.get('risk_assessment', 'N/A')}

*Root Cause:*
{analysis.get('root_cause_analysis', 'N/A')}

*Potential Impact:*
{analysis.get('potential_impact', 'N/A')}

h2. Recommended Actions
{self._format_actions(analysis.get('recommended_actions', []))}

h2. Indicators of Compromise
{self._format_indicators(alert.get('indicators', []))}
"""

            # Create the ticket
            issue_dict = {
                'project': self.project_key,
                'summary': summary,
                'description': description,
                'issuetype': {'name': self.issue_type},
                'priority': self._map_severity_to_priority(alert.get('severity', 'medium')),
                'labels': ['security-incident', 'automated-alert']
            }
            
            new_issue = self.jira.create_issue(fields=issue_dict)
            
            # Add any attachments or additional fields
            self._add_custom_fields(new_issue, alert, analysis)
            
            logger.info(f"Created Jira ticket: {new_issue.key}")
            return new_issue.key
            
        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {str(e)}")
            return None
            
    def _format_actions(self, actions: list) -> str:
        """Format recommended actions as Jira markup."""
        if not actions:
            return "No actions specified"
        return "\n".join([f"* {action}" for action in actions])
        
    def _format_indicators(self, indicators: list) -> str:
        """Format IOCs as Jira markup."""
        if not indicators:
            return "No indicators available"
        return "\n".join([f"* {ind.get('type', 'unknown')}: {ind.get('value', 'N/A')}" 
                         for ind in indicators])
        
    def _map_severity_to_priority(self, severity: str) -> Dict[str, str]:
        """Map alert severity to Jira priority."""
        priority_map = {
            'critical': {'name': 'Highest'},
            'high': {'name': 'High'},
            'medium': {'name': 'Medium'},
            'low': {'name': 'Low'}
        }
        return priority_map.get(severity.lower(), {'name': 'Medium'})
        
    def _add_custom_fields(self, issue, alert: Dict[str, Any], analysis: Dict[str, Any]):
        """Add any custom fields or attachments to the ticket."""
        try:
            # Example: Add MITRE ATT&CK technique as a custom field
            if 'technique' in alert:
                self.jira.issue(issue.id, fields={
                    'customfield_10100': alert['technique']  # Assuming this is your custom field ID
                })
        except Exception as e:
            logger.warning(f"Failed to add custom fields: {str(e)}")
