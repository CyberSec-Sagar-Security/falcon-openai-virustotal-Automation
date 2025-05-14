import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text

from utils.falcon_api import fetch_crowdstrike_alerts
from utils.openai_analysis import analyze_alert_with_openai
from utils.teams_notifier import send_to_teams
from utils.formatter import generate_summary_report
from utils.mitre_analyzer import MitreAnalyzer
from utils.threat_intel import ThreatIntelligence
from utils.response_automation import ResponseAutomation
from utils.incident_manager import IncidentManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_with_sample_alert():
    """Test the entire workflow using a sample alert."""
    print("\nStarting Enhanced Test Workflow")
    
    console = Console()
    results_table = Table(title="Test Results")
    results_table.add_column("Component")
    results_table.add_column("Status")
    results_table.add_column("Details")
    
    # Test Component 1: Configuration and Data Loading
    try:
        with open('test_data/sample_alert.json', 'r') as f:
            sample_alert = json.load(f)
        with open('config.json', 'r') as f:
            config = json.load(f)
        results_table.add_row("Config/Data Loading", "PASS", "Successfully loaded configuration and sample data")
    except Exception as e:
        results_table.add_row("Config/Data Loading", "FAIL", f"Error: {str(e)}")
        console.print(results_table)
        return False

    # Test Component 2: MITRE ATT&CK Analysis
    try:
        mitre = MitreAnalyzer()
        technique_id = sample_alert.get('technique', '').split()[0]
        mitre_result = mitre.analyze_technique(technique_id)
        if mitre_result and mitre_result.get('success'):
            results_table.add_row(
                "MITRE Analysis",
                "PASS",
                f"Successfully analyzed technique {technique_id}"
            )
        else:
            results_table.add_row(
                "MITRE Analysis",
                "WARN",
                "No MITRE data found but component working"
            )
    except Exception as e:
        results_table.add_row("MITRE Analysis", "FAIL", f"Error: {str(e)}")

    # Test Component 3: Threat Intelligence
    try:
        threat_intel = ThreatIntelligence(config)
        intel_results = []
        for indicator in sample_alert.get('indicators', []):
            result = threat_intel.enrich_ioc(
                indicator.get('value'),
                indicator.get('type')
            )
            intel_results.append(result)
        
        results_table.add_row(
            "Threat Intel",
            "PASS",
            f"Processed {len(intel_results)} indicators"
        )
    except Exception as e:
        results_table.add_row("Threat Intel", "FAIL", f"Error: {str(e)}")

    # Test Component 4: OpenAI Analysis
    try:
        enriched_result = analyze_alert_with_openai(sample_alert, config, return_usage=True)
        if 'error' in enriched_result:
            raise Exception(enriched_result['error'])
        results_table.add_row(
            "OpenAI Analysis",
            "PASS",
            "Successfully analyzed alert"
        )
    except Exception as e:
        results_table.add_row("OpenAI Analysis", "FAIL", f"Error: {str(e)}")

    # Test Component 5: Response Automation
    try:
        response = ResponseAutomation(config)
        automation_result = response.evaluate_and_respond(sample_alert, enriched_result)
        status = "PASS" if automation_result.get('status') == 'completed' else "WARN"
        results_table.add_row(
            "Response Automation",
            status,
            f"Status: {automation_result.get('status', 'unknown')}"
        )
    except Exception as e:
        results_table.add_row("Response Automation", "FAIL", f"Error: {str(e)}")

    # Test Component 6: Incident Management
    try:
        incident_mgr = IncidentManager(config)
        ticket_id = incident_mgr.create_incident_ticket(sample_alert, enriched_result)
        if ticket_id:
            results_table.add_row(
                "Incident Management",
                "PASS",
                f"Created ticket: {ticket_id}"
            )
        else:
            results_table.add_row(
                "Incident Management",
                "WARN",
                "Skipped (no Jira config)"
            )
    except Exception as e:
        results_table.add_row("Incident Management", "FAIL", f"Error: {str(e)}")

    # Test Component 7: Teams Notification
    try:
        formatted_message = generate_summary_report(sample_alert, enriched_result)
        send_result = send_to_teams(formatted_message, config)
        status = "PASS" if send_result else "WARN"
        results_table.add_row(
            "Teams Notification",
            status,
            "Sent successfully" if send_result else "Webhook not configured"
        )
    except Exception as e:
        results_table.add_row("Teams Notification", "FAIL", f"Error: {str(e)}")

    # Print Results
    console.print("\nTest Results:")
    console.print(results_table)

    # Check if any critical components failed
    critical_components = ["Config/Data Loading", "OpenAI Analysis", "Teams Notification"]
    failures = [row for row in results_table.rows if row[0] in critical_components and "FAIL" in row[1]]
    
    if failures:
        console.print("\nCritical component(s) failed. Please fix before deploying.", style="red")
        return False
    else:
        console.print("\nAll critical components passed!", style="green")
        return True

if __name__ == "__main__":
    test_with_sample_alert()
