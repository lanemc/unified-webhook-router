import json
from typing import Dict, Any
from ..types import WebhookProvider
from ..utils import compute_hmac_base64, timing_safe_compare


class SquareProvider(WebhookProvider):
    @property
    def name(self) -> str:
        return 'square'
    
    def identify(self, headers: Dict[str, str], body: bytes) -> bool:
        return 'x-square-hmacsha256-signature' in headers
    
    def verify(self, headers: Dict[str, str], raw_body: bytes, config: Dict[str, Any]) -> bool:
        signature = headers.get('x-square-hmacsha256-signature')
        if not signature or not config.get('signature_key') or not config.get('notification_url'):
            return False
        
        # Square uses notification URL + raw body as the message
        message = config['notification_url'] + raw_body.decode('utf-8')
        expected_signature = compute_hmac_base64('sha256', config['signature_key'], message)
        
        return timing_safe_compare(signature, expected_signature)
    
    def extract_event_type(self, headers: Dict[str, str], payload: Any) -> str:
        return payload.get('type', '')
    
    def parse_payload(self, raw_body: bytes, headers: Dict[str, str]) -> Any:
        return json.loads(raw_body.decode('utf-8'))