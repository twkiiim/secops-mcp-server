import os
import logging
import json
import sys
from typing import Any, Optional
from secops import SecOpsClient

logger = logging.getLogger("secops-mcp-utils")

DEFAULT_PROJECT_ID = os.environ.get("CHRONICLE_PROJECT_ID")
DEFAULT_CUSTOMER_ID = os.environ.get("CHRONICLE_CUSTOMER_ID")
DEFAULT_REGION = os.environ.get("CHRONICLE_REGION", "us")

class MyChronicleWrapper:
    def __init__(self, real_chronicle):
        self.real_chronicle = real_chronicle
    
    def translate_nl_to_udm(self, text: str) -> str:
        # Simple rule-based translation for testing
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        if ips:
            return f'principal.ip = "{ips[0]}" or target.ip = "{ips[0]}"'
        
        user_pattern = r"user '([^']+)'"
        users = re.findall(user_pattern, text)
        if users:
            return f'principal.user.userid = "{users[0]}"'
            
        return text # Fallback to returning the text itself
        
    def search_udm(self, **kwargs):
        return self.real_chronicle.search_udm(**kwargs)
        
    def __getattr__(self, name):
        return getattr(self.real_chronicle, name)

def get_chronicle_client(
    project_id: Optional[str] = None, 
    customer_id: Optional[str] = None, 
    region: Optional[str] = None
) -> Any:
    project_id = project_id or DEFAULT_PROJECT_ID
    customer_id = customer_id or DEFAULT_CUSTOMER_ID
    region = region or DEFAULT_REGION

    if not project_id or not customer_id:
        logger.error("Missing Project ID or Customer ID")
        return None

    # 1. Determine the directory where THIS script lives
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Look for the key file in the same directory
    sa_key_path = os.path.join(base_dir, "service_account.json")

    logger.info(f"Attempting to load SA Key from: {sa_key_path}")

    if not os.path.exists(sa_key_path):
        logger.warning(f"Key file NOT found at {sa_key_path}. Attempting to use default credentials.")
        try:
            logger.info(f"Initializing SecOps Client with default credentials for Region: {region}")
            client = SecOpsClient()
            chronicle = client.chronicle(customer_id=customer_id, project_id=project_id, region=region)
            return MyChronicleWrapper(chronicle)
        except Exception as e:
            logger.error(f"Failed to initialize SecOps client with default credentials: {e}")
            return None

    try:
        with open(sa_key_path, 'r') as f:
            service_account_info = json.load(f)

        logger.info(f"Initializing SecOps Client for Region: {region}")
        client = SecOpsClient(service_account_info=service_account_info)
        chronicle = client.chronicle(customer_id=customer_id, project_id=project_id, region=region)
        return MyChronicleWrapper(chronicle)
    except Exception as e:
        logger.error(f"Failed to initialize SecOps client: {e}")
        import traceback
        traceback.print_exc()
        return None
