import requests
import logging
import time
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TeamsNotifierError(Exception):
    pass

def send_to_teams(message: str, config: Dict[str, Any]) -> bool:
    """Send formatted message to Microsoft Teams channel."""
    webhook_url = config['teams']['webhook_url']
    
    # Prepare the Teams message card
    teams_message = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "Security Alert",
        "themeColor": "0072C6",
        "text": message
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(
                webhook_url,
                json=teams_message,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            
            logger.info("Successfully sent alert to Teams")
            return True
            
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to send to Teams after {max_retries} attempts: {str(e)}")
                return False
            
            wait_time = 2 ** attempt  # Exponential backoff
            logger.warning(f"Retry {attempt + 1}/{max_retries} after error: {str(e)}")
            time.sleep(wait_time)
    
    return False