import json
from typing import Dict, Any
from urllib.parse import parse_qs
from ..types import WebhookProvider
from ..utils import compute_hmac, timing_safe_compare, is_within_tolerance


class SlackProvider(WebhookProvider):
    @property
    def name(self) -> str:
        return 'slack'
    
    def identify(self, headers: Dict[str, str], body: bytes) -> bool:
        return 'x-slack-signature' in headers and 'x-slack-request-timestamp' in headers
    
    def verify(self, headers: Dict[str, str], raw_body: bytes, config: Dict[str, Any]) -> bool:
        signature = headers.get('x-slack-signature')
        timestamp = headers.get('x-slack-request-timestamp')
        
        if not signature or not timestamp or not config.get('signing_secret'):
            return False
        
        timestamp_num = int(timestamp)
        tolerance = config.get('tolerance', 300)  # 5 minutes default
        
        if not is_within_tolerance(timestamp_num, tolerance):
            return False
        
        base_string = f"v0:{timestamp}:{raw_body.decode('utf-8')}"
        expected_signature = f"v0={compute_hmac('sha256', config['signing_secret'], base_string)}"
        
        return timing_safe_compare(signature, expected_signature)
    
    def extract_event_type(self, headers: Dict[str, str], payload: Any) -> str:
        # Handle different Slack event types
        if payload.get('type') == 'url_verification':
            return 'url_verification'
        elif payload.get('type') == 'event_callback' and payload.get('event'):
            return payload['event'].get('type', '')
        elif payload.get('command'):
            return payload['command']  # Slash commands
        elif payload.get('type'):
            return payload['type']
        return ''
    
    def parse_payload(self, raw_body: bytes, headers: Dict[str, str]) -> Any:
        content_type = headers.get('content-type', '')
        
        if 'application/x-www-form-urlencoded' in content_type:
            # Parse form data for slash commands
            parsed = parse_qs(raw_body.decode('utf-8'))
            # Convert single-item lists to strings
            payload = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            return payload
        else:
            # Parse JSON for Events API
            return json.loads(raw_body.decode('utf-8'))