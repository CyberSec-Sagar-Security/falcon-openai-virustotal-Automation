import json
import os
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from utils.module_manager import ModuleManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('falcon_enricher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnrichmentError(Exception):
    """Custom exception for enrichment pipeline failures."""
    pass

def load_config() -> Dict[str, Any]:
    """Load and validate configuration."""
    try:
        with open("config.json", 'r') as f:
            config = json.load(f)
            
        required_keys = ['crowdstrike', 'enabled_modules', 'workflow']
        for key in required_keys:
            if key not in config:
                raise EnrichmentError(f"Missing required config section: {key}")
        
        return config
    except json.JSONDecodeError as e:
        raise EnrichmentError(f"Invalid config.json format: {str(e)}")
    except FileNotFoundError:
        raise EnrichmentError("config.json not found")

class SecurityAlertProcessor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize module manager
        self.module_manager = ModuleManager(config)
        
        # Initialize core modules
        orchestrator_module = self.module_manager.load_module('orchestrator')
        self.orchestrator = orchestrator_module.Orchestrator(config) if orchestrator_module else None
        
        # Initialize optional modules
        self.sandbox_analyzer = None
        self.threat_intel = None
        
        if self.module_manager.is_module_enabled('sandbox_analysis'):
            sandbox_module = self.module_manager.load_module('sandbox_analyzer')
            if sandbox_module:
                self.sandbox_analyzer = sandbox_module.SandboxAnalyzer(config)
                
        if self.module_manager.is_module_enabled('threat_intel'):
            threat_intel_module = self.module_manager.load_module('threat_intel')
            if threat_intel_module:
                self.threat_intel = threat_intel_module.ThreatIntelligence(config)

    def _should_run_sandbox_analysis(self, alert: Dict[str, Any]) -> bool:
        """Determine if sandbox analysis should be run for this alert."""
        if not self.module_manager.is_module_enabled('sandbox_analysis'):
            return False
            
        # Check if alert contains file indicators
        has_file = any(
            indicator.get('type') == 'file' 
            for indicator in alert.get('indicators', [])
        )
        
        return has_file

    async def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single alert through the enhanced workflow."""
        alert_id = alert.get('id', 'N/A')
        self.logger.info(f"Processing alert {alert_id}")
        
        results = {
            "status": "processing",
            "alert_id": alert_id,
            "enrichments": [],
            "sandbox_result": None,
            "analysis": None,
            "ticket": None
        }

        try:
            # Create Jira ticket if enabled
            if self.module_manager.is_module_enabled('jira_integration'):
                incident_module = self.module_manager.load_module('incident_manager')
                if incident_module:
                    results['ticket'] = await incident_module.create_jira_ticket(alert, self.config)

            # Prepare enrichment tasks
            enrichment_tasks = []
            
            if self.threat_intel:
                enrichment_tasks.extend([
                    lambda a: self.threat_intel.check_virustotal(a),
                    lambda a: self.threat_intel.check_alienvault(a)
                ])
            
            if self.module_manager.is_module_enabled('mitre_mapping'):
                mitre_module = self.module_manager.load_module('mitre_analyzer')
                if mitre_module:
                    enrichment_tasks.append(lambda a: mitre_module.analyze_mitre_tactics(a))

            # Run enrichment tasks in parallel
            if enrichment_tasks and self.orchestrator:
                results['enrichments'] = await self.orchestrator.run_parallel_tasks(
                    enrichment_tasks, 
                    alert
                )

            # Run sandbox analysis if needed
            if self.sandbox_analyzer and self._should_run_sandbox_analysis(alert):
                self.logger.info(f"Starting sandbox analysis for alert {alert_id}")
                results['sandbox_result'] = await self.sandbox_analyzer.submit_for_analysis(
                    alert.get('file_path')
                )

            # Run OpenAI analysis if enabled
            if self.module_manager.is_module_enabled('openai_analysis'):
                openai_module = self.module_manager.load_module('openai_analysis')
                if openai_module:
                    results['analysis'] = await openai_module.analyze_alert_with_openai(
                        {
                            "alert": alert,
                            "enrichments": results['enrichments'],
                            "sandbox_result": results['sandbox_result']
                        }, 
                        self.config
                    )

            # Update ticket and send notifications
            await self._update_and_notify(
                results['ticket'],
                alert,
                results['enrichments'],
                results['sandbox_result'],
                results['analysis']
            )

            results['status'] = 'success'
            return results

        except Exception as e:
            self.logger.error(f"Error processing alert {alert_id}: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)
            return results

    async def _update_and_notify(
        self,
        ticket: Optional[Dict[str, Any]],
        alert: Dict[str, Any],
        enrichments: List[Dict[str, Any]],
        sandbox_result: Optional[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]]
    ) -> None:
        """Update ticket and send notifications."""
        try:
            # Update Jira ticket if enabled
            if ticket and self.module_manager.is_module_enabled('jira_integration'):
                incident_module = self.module_manager.load_module('incident_manager')
                if incident_module:
                    await incident_module.update_jira_ticket(
                        ticket["id"],
                        {
                            "enrichments": enrichments,
                            "sandbox_result": sandbox_result,
                            "analysis": analysis
                        },
                        self.config
                    )
            
            # Send Teams notification if enabled
            if self.module_manager.is_module_enabled('teams_notifications'):
                teams_module = self.module_manager.load_module('teams_notifier')
                formatter_module = self.module_manager.load_module('formatter')
                
                if teams_module and formatter_module:
                    formatted_message = formatter_module.generate_summary_report(
                        alert,
                        enrichments,
                        sandbox_result,
                        analysis
                    )
                    await teams_module.send_to_teams(formatted_message, self.config)
        
        except Exception as e:
            self.logger.error(f"Error in update_and_notify: {str(e)}")
            raise

async def main() -> None:
    """Main execution flow with enhanced error handling."""
    start_time = datetime.now()
    logger.info("Starting Enhanced Falcon Alert Enricher Pipeline")
    
    try:
        # Load configuration
        config = load_config()
        logger.info("Configuration loaded successfully")
        
        # Initialize processor
        processor = SecurityAlertProcessor(config)
        
        # Fetch alerts
        falcon_module = processor.module_manager.load_module('falcon_api')
        if not falcon_module:
            raise EnrichmentError("Failed to load Falcon API module")
            
        logger.info("Fetching alerts from CrowdStrike Falcon...")
        alerts = await falcon_module.fetch_crowdstrike_alerts(config)
        
        if not alerts:
            logger.info("No alerts found or API failure")
            return
            
        # Process alerts
        total_alerts = len(alerts)
        results = []
        
        for alert in alerts:
            result = await processor.process_alert(alert)
            results.append(result)
                
        # Summary
        successful = sum(1 for r in results if r["status"] == "success")
        failed = sum(1 for r in results if r["status"] == "error")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info(
            f"Completed processing {total_alerts} alerts in {duration:.2f} seconds. "
            f"Successful: {successful}, Failed: {failed}"
        )
        
    except Exception as e:
        logger.error(f"Critical error in main execution: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
