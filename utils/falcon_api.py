import requests
import logging
from datetime import datetime, timedelta
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FalconAPIError(Exception):
    pass

def get_falcon_token(config):
    """Get OAuth2 token from CrowdStrike Falcon API."""
    try:
        auth_url = f"{config['crowdstrike']['base_url']}/oauth2/token"
        data = {
            'client_id': config['crowdstrike']['client_id'],
            'client_secret': config['crowdstrike']['client_secret']
        }
        response = requests.post(auth_url, data=data)
        response.raise_for_status()
        return response.json()['access_token']
    except Exception as e:
        logger.error(f"Failed to get Falcon token: {str(e)}")
        raise FalconAPIError(f"Authentication failed: {str(e)}")

def fetch_crowdstrike_alerts(config, time_range_hours=24):
    """
    Fetch alerts from CrowdStrike Falcon API.
    
    Args:
        config (dict): Configuration dictionary
        time_range_hours (int): Number of hours to look back for alerts (default: 24)
    """
    try:
        token = get_falcon_token(config)
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }

        # Set time filter
        start_time = (datetime.utcnow() - timedelta(hours=time_range_hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Build query for alerts
        filter_conditions = [
            f'created_timestamp:>=\'{start_time}\'',
            f'severity:\"{config["crowdstrike"]["severity_threshold"]}\"'
        ]

        # Add custom filters if specified
        if 'additional_filters' in config['crowdstrike']:
            filter_conditions.extend(config['crowdstrike']['additional_filters'])

        query_params = {
            'filter': '+'.join(filter_conditions),
            'sort': 'created_timestamp|desc',
            'limit': config['crowdstrike']['max_alerts']
        }

        alerts_url = f"{config['crowdstrike']['base_url']}/alerts/queries/alerts/v1"
        response = requests.get(alerts_url, headers=headers, params=query_params)
        response.raise_for_status()
        
        alert_ids = response.json().get('resources', [])
        if not alert_ids:
            logger.info("No alerts found matching criteria")
            return []

        # Get detailed information for each alert
        details_url = f"{config['crowdstrike']['base_url']}/alerts/entities/alerts/v1"
        detailed_alerts = []
        
        # Process alerts in batches of 10
        for i in range(0, len(alert_ids), 10):
            batch = alert_ids[i:i+10]
            params = {'ids': batch}
            response = requests.get(details_url, headers=headers, params=params)
            response.raise_for_status()
            detailed_alerts.extend(response.json().get('resources', []))
            time.sleep(1)  # Rate limiting

        return detailed_alerts

    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return []