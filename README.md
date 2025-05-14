# Falcon Alert Enricher

An advanced security automation pipeline that enriches CrowdStrike Falcon alerts with AI-powered analysis and delivers enhanced reports to Microsoft Teams.

## Features

* **CrowdStrike Falcon Integration**: 
  - Fetches high-severity security alerts via Falcon API
  - Configurable time range filtering
  - Batch processing with rate limiting
* **AI-Powered Analysis**: 
  - Leverages OpenAI GPT-4 for deep alert analysis
  - Token usage tracking and optimization
  - Structured JSON output
* **Rich Reporting**: 
  - Risk Assessment
  - Root Cause Analysis
  - Potential Impact Analysis
  - Recommended Actions
* **MITRE ATT&CK Integration**:
  - Automatic technique mapping
  - Tactic identification
  - Common mitigation strategies
* **Threat Intelligence**:
  - VirusTotal integration
  - AlienVault OTX lookup
  - IOC enrichment
* **Response Automation**:
  - Automatic host isolation for critical threats
  - Evidence collection
  - Configurable response actions
* **Incident Management**:
  - Automatic Jira ticket creation
  - Rich ticket formatting
  - Custom field mapping
* **Teams Integration**: 
  - Rich message formatting
  - Webhook delivery with retry logic
  - Interactive card support
* **Resilient Operations**: 
  - Comprehensive error handling
  - Retry logic with exponential backoff
  - Rate limiting support
* **Comprehensive Logging**: 
  - Detailed logging with rotation
  - Performance metrics
  - API usage tracking

## Prerequisites

* Required:
  - Python 3.8+
  - CrowdStrike Falcon API credentials
  - OpenAI API key
  - Microsoft Teams webhook URL
* Optional:
  - Jira API credentials
  - VirusTotal API key
  - AlienVault OTX API key

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd falcon_alert_enricher
```

2. Install core requirements:
```bash
pip install -r requirements/core.txt
```

3. Install optional modules based on your needs:
```bash
# For OpenAI analysis
pip install -r requirements/openai.txt

# For Jira integration
pip install -r requirements/jira.txt

# For Teams notifications
pip install -r requirements/teams.txt

# For threat intelligence
pip install -r requirements/threat_intel.txt

# For sandbox analysis
pip install -r requirements/sandbox.txt

# For response automation
pip install -r requirements/response_automation.txt
```

4. Configure the application:
- Copy `config.json.example` to `config.json`
- Enable/disable modules in the config:
```json
{
    "enabled_modules": {
        "sandbox_analysis": true,    // Set to false to disable
        "threat_intel": true,       // Set to false to disable
        "jira_integration": true,   // Set to false to disable
        "teams_notifications": true,// Set to false to disable
        "openai_analysis": true,    // Set to false to disable
        "mitre_mapping": true,      // Set to false to disable
        "response_automation": true // Set to false to disable
    }
}
```
- Fill in API credentials only for enabled modules

## Configuration

The config.json file supports extensive customization:

```json
{
    "crowdstrike": {
        "client_id": "YOUR_FALCON_CLIENT_ID",
        "client_secret": "YOUR_FALCON_CLIENT_SECRET",
        "base_url": "https://api.crowdstrike.com",
        "severity_threshold": "high",
        "max_alerts": 50
    },
    "openai": {
        "api_key": "YOUR_OPENAI_API_KEY",
        "model": "gpt-4-turbo-preview",
        "temperature": 0.3,
        "max_tokens": 1000
    },
    "teams": {
        "webhook_url": "YOUR_TEAMS_WEBHOOK_URL"
    },
    "jira": {
        "server_url": "https://your-instance.atlassian.net",
        "username": "your-email@company.com",
        "api_token": "YOUR_JIRA_API_TOKEN",
        "project_key": "SEC",
        "issue_type": "Security Incident"
    },
    "virustotal": {
        "api_key": "YOUR_VIRUSTOTAL_API_KEY"
    },
    "alienvault": {
        "api_key": "YOUR_ALIENVAULT_API_KEY"
    },
    "response_automation": {
        "enabled": true,
        "auto_isolate_threshold": "critical",
        "allowed_actions": ["isolate_host", "collect_evidence"]
    }
}
```

## Modularity

The project is designed to be highly modular, allowing you to enable or disable features based on your needs:

### Core Modules (Required)
- CrowdStrike Falcon Integration
- Parallel Processing
- Basic Alert Handling

### Optional Modules
1. **OpenAI Analysis Module**
   - AI-powered alert analysis
   - Cost: Based on OpenAI API usage
   - Enable/Disable: Set `openai_analysis` in config

2. **Sandbox Analysis Module**
   - File analysis in isolated environment
   - Requirements: Sandbox API access
   - Enable/Disable: Set `sandbox_analysis` in config

3. **Threat Intelligence Module**
   - VirusTotal integration
   - AlienVault OTX lookup
   - Enable/Disable: Set `threat_intel` in config

4. **MITRE Mapping Module**
   - Technique and tactic identification
   - Enable/Disable: Set `mitre_mapping` in config

5. **Jira Integration Module**
   - Automatic ticket creation
   - Enable/Disable: Set `jira_integration` in config

6. **Teams Notification Module**
   - Teams webhook integration
   - Enable/Disable: Set `teams_notifications` in config

7. **Response Automation Module**
   - Automated security actions
   - Enable/Disable: Set `response_automation` in config

### Module Configuration Example
```json
{
    "enabled_modules": {
        "sandbox_analysis": false,     // Disabled
        "threat_intel": true,          // Enabled
        "jira_integration": true,      // Enabled
        "teams_notifications": true,    // Enabled
        "openai_analysis": false,      // Disabled
        "mitre_mapping": true,         // Enabled
        "response_automation": false    // Disabled
    }
}
```

### Installation by Module
Each module has its own requirements file in the `requirements/` directory:
```bash
# Install only what you need
pip install -r requirements/core.txt        # Required
pip install -r requirements/threat_intel.txt # Optional
pip install -r requirements/jira.txt        # Optional
# etc...
```

## Usage

1. Run the main script:
```bash
python main.py
```

2. Run with specific time range:
```bash
python main.py --hours 6  # Process last 6 hours of alerts
```

3. Run tests:
```bash
python test_workflow.py
```

## Testing

The project includes comprehensive testing capabilities:

1. Component Tests:
- Configuration loading
- MITRE ATT&CK integration
- Threat Intelligence enrichment
- OpenAI analysis
- Response automation
- Incident management
- Teams notification

2. Sample Data:
- `test_data/sample_alert.json` provides a realistic alert
- Includes various IOC types
- Contains MITRE technique information

3. Test Output:
```
 Test Results:
┌───────────────────┬──────────┬───────────────────────┐
│ Component         │ Status   │ Details               │
├───────────────────┼──────────┼───────────────────────┤
│ Config Loading    │  PASS   │ Successfully loaded  │
│ MITRE Analysis    │  PASS   │ Analyzed T1059.001   │
│ Threat Intel      │  PASS   │ Processed 4 IOCs     │
│ OpenAI Analysis   │  PASS   │ Analysis complete    │
│ Response Auto     │  PASS   │ Actions executed     │
│ Incident Mgmt     │  PASS   │ Ticket SEC-123       │
│ Teams Notification│  PASS   │ Message delivered    │
└───────────────────┴──────────┴───────────────────────┘
```

## Project Structure

```
falcon_alert_enricher/
├── config.json             # Configuration file
├── main.py                # Main execution script
├── README.md              # Documentation
├── requirements/          # Module-specific dependencies
│   ├── core.txt          # Core requirements
│   ├── jira.txt          # Jira integration
│   ├── openai.txt        # OpenAI analysis
│   ├── sandbox.txt       # Sandbox analysis
│   └── threat_intel.txt  # Threat intelligence
├── terraform/            # Infrastructure as code
│   └── main.tf          # Terraform configuration
├── test_workflow.py      # Test suite
├── test_data/           # Test data directory
│   └── sample_alert.json # Sample alert for testing
└── utils/               # Utility modules
    ├── falcon_api.py    # CrowdStrike Falcon API
    ├── formatter.py     # Message formatting
    ├── incident_manager.py# Jira integration
    ├── mitre_analyzer.py # MITRE ATT&CK integration
    ├── openai_analysis.py# OpenAI integration
    ├── response_automation.py # Automated responses
    ├── teams_notifier.py # Teams webhook handler
    └── threat_intel.py   # Threat intel enrichment
```

## Security Considerations

### Authentication & Authorization
* Store API keys securely using environment variables or secrets management
* Regularly rotate all API credentials
* Implement proper access controls and RBAC

### Monitoring & Auditing
* Monitor API usage and costs
* Track automated actions and responses
* Regular security testing and reviews
* Audit logs for suspicious activities

### Data Protection
* Review OpenAI's data handling policies
* Implement data retention policies
* Encrypt sensitive data at rest and in transit

### Best Practices
* Follow least privilege principle
* Regular security assessments
* Keep all dependencies updated
* Monitor for security advisories

## License

MIT License - See LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Development Guidelines
* Follow PEP 8 style guide
* Add unit tests for new features
* Update documentation
* Follow semantic versioning

## Support

### Getting Help
1. Check the [FAQ](docs/FAQ.md)
2. Review the documentation
3. Open an issue in the GitHub repository
4. Contact the security team

### Reporting Issues
* Use the issue template
* Include reproducible examples
* Attach relevant logs
* Specify your environment

## Example Output

Here's how the enhanced alert looks in Teams:

```
[ALERT] CrowdStrike Alert: Suspicious PowerShell Script Execution
Host: WIN-PROD-SERVER01
Severity: CRITICAL
Timestamp: 14-May-2025 10:15AM

MITRE ATT&CK:
* Technique: T1059.001 - PowerShell
* Tactics: Execution, Defense Evasion

AI Analysis:
| Category         | Details                                                  |
|-----------------|----------------------------------------------------------|
| Risk Assessment | Critical - Encoded PowerShell execution from SYSTEM context|
| Root Cause      | Suspicious encoded PowerShell command execution           |
| Potential Impact| Possible credential theft, lateral movement               |

Recommended Actions:
* Isolate host immediately
* Collect memory dump and logs
* Reset affected credentials
* Block suspicious IP: 185.147.53.44

Enriched IOCs:
* IP 185.147.53.44 - Known C2 server (VirusTotal: 16/85)
* Hash matched recent ransomware campaign

---
Generated by AI Security Analyst
```