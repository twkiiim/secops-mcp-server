# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Security Operations MCP tools for entity lookup."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from server import get_chronicle_client, server


# Configure logging
logger = logging.getLogger('secops-mcp')

@server.tool()
async def lookup_entity(
    entity_value: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    hours_back: int = 24,
    region: Optional[str] = None,
) -> str:
    """Look up an entity (IP, domain, hash, user, etc.) in Chronicle SIEM for enrichment.

    Provides a comprehensive summary of an entity's activity based on historical log data
    within Chronicle over a specified time period. This tool queries Chronicle SIEM directly.
    Chronicle automatically attempts to detect the entity type from the value provided.

    **Workflow Integration:**
    - Use this tool after identifying key entities (IPs, domains, users, hashes) from any source
      (e.g., an alert, a SOAR case, threat intelligence report, cloud posture finding).
    - Provides historical context and activity summary for an entity directly from SIEM logs.
    - Complements information available in other security platforms (SOAR, EDR, Cloud Security)
      by offering a log-centric perspective.
    - Helps understand available data when troubleshooting detection rule issues.

    **Use Cases:**
    - Quickly understand the context and prevalence of indicators (e.g., '192.168.1.1',
      'evil.com', 'user@example.com', 'hashvalue') by examining SIEM log data.
    - Reveal historical context, broader relationships, or activity patterns potentially
      missed by other tools.
    - Enrich entities identified in alerts, cases, or reports with SIEM-derived context.

    **Output Summary:**
    The summary includes information observed within the specified time window (`hours_back`):
    - Primary entity details (type, first/last seen within the window).
    - Related entities observed interacting with the primary entity in logs.
    - Associated Chronicle alerts triggered involving the entity within the window.
    - Timeline summary (event/alert counts over the specified period).
    - Prevalence information (if available).

    Args:
        entity_value (str): Value to look up (e.g., IP address, domain name, file hash, username).
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        hours_back (int): How many hours of historical data to consider for the summary. Defaults to 24.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        str: A formatted string summarizing the entity information found in Chronicle within the specified time window,
             including first/last seen, related entities, and associated alerts.
             Returns 'No information found...' if the entity is not found in the specified timeframe.

    Example Usage:
        lookup_entity(entity_value="198.51.100.10", hours_back=72)

    Next Steps (using MCP-enabled tools):
        - Analyze the summary for suspicious patterns or relationships.
        - If more detailed event logs are needed, use a tool to search SIEM events
          (like `search_security_events`) targeting this entity's value.
        - Correlate findings with data from other security tools (e.g., EDR IoAs, network alerts,
          cloud posture findings, user risk scores) via their respective MCP tools.
        - Document findings in a relevant case management or ticketing system using an appropriate MCP tool.
    """
    try:
        from utils import DEFAULT_PROJECT_ID, DEFAULT_CUSTOMER_ID, DEFAULT_REGION
        from secops.chronicle.client import _detect_value_type
        
        project_id = project_id or DEFAULT_PROJECT_ID
        customer_id = customer_id or DEFAULT_CUSTOMER_ID
        region = region or DEFAULT_REGION
        
        base_url = f"https://{region}-chronicle.googleapis.com/v1alpha"
        instance_id = f"projects/{project_id}/locations/{region}/instances/{customer_id}"
        url = f"{base_url}/{instance_id}:summarizeEntity"

        chronicle = get_chronicle_client(project_id, customer_id, region)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        params = {
            "timeRange.startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "timeRange.endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "returnAlerts": True,
            "returnPrevalence": False,
            "includeAllUdmEventTypesForFirstLastSeen": True,
            "pageSize": 1000
        }

        detected_field_path, detected_value_type = _detect_value_type(entity_value)
        if detected_field_path:
            params["fieldAndValue.fieldPath"] = detected_field_path
            params["fieldAndValue.value"] = entity_value
        elif detected_value_type:
            params["fieldAndValue.value"] = entity_value
            params["fieldAndValue.valueType"] = detected_value_type
        else:
            raise ValueError(f"Could not determine type for value: {entity_value}")

        # Make raw HTTP call using the authorized session
        response = chronicle.session.get(url, params=params)
        
        if response.status_code != 200:
            return f'Error getting entity summary: {response.text}'
            
        data = response.json()
        
        # Process JSON data manually to avoid NoneType errors
        entities = data.get("entities", [])
        if not entities:
            return f'No information found for entity: {entity_value}'

        result = f'Entity Summary for {entity_value}:\n\n'
        
        # Process primary entity
        if entities:
            primary_entity = entities[0]
            result += f'Primary Entity:\n'
            
            metadata = primary_entity.get("metadata", {})
            entity_type = metadata.get("entityType", "Unknown")
            
            metric = primary_entity.get("metric", {})
            first_seen = metric.get("firstSeen", "Unknown")
            last_seen = metric.get("lastSeen", "Unknown")
            
            result += f'Entity Type: {entity_type}\n'
            result += f'First Seen: {first_seen}\n'
            result += f'Last Seen: {last_seen}\n\n'

        # Process related entities
        if len(entities) > 1:
            result += f'Related Entities ({len(entities) - 1}):\n'
            for i, entity in enumerate(entities[1:6], 1): # Limit to 5
                metadata = entity.get("metadata", {})
                entity_type = metadata.get("entityType", "Unknown")
                result += f'{i}. Type: {entity_type}\n'
            
            if len(entities) > 6:
                result += f'... and {len(entities) - 6} more related entities\n'
            result += '\n'

        # Process alert counts
        alert_counts = data.get("alertCounts", [])
        if alert_counts:
            result += 'Associated Alerts:\n'
            for alert in alert_counts:
                rule = alert.get("rule", "Unknown")
                count = alert.get("count", 0)
                result += f'- Rule: {rule}, Count: {count}\n'
            result += '\n'

        # Add timeline information if available
        timeline_data = data.get("timeline", {})
        if timeline_data:
            buckets = timeline_data.get("buckets", [])
            if buckets:
                total_events = sum(int(bucket.get("eventCount", 0)) for bucket in buckets)
                total_alerts = sum(int(bucket.get("alertCount", 0)) for bucket in buckets)
                result += 'Timeline Summary:\n'
                result += f'Total Events: {total_events}\n'
                result += f'Total Alerts: {total_alerts}\n\n'

        return result
        
    except Exception as e:
        logger.error(f'Error looking up entity: {str(e)}', exc_info=True)
        return f'Error looking up entity: {str(e)}'
