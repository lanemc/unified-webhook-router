import json
from typing import Dict, Any
from ..types import WebhookProvider
from ..utils import compute_hmac, timing_safe_compare, is_within_tolerance


class StripeProvider(WebhookProvider):
    @property
    def name(self) -> str:
        return 'stripe'
    
    def identify(self, headers: Dict[str, str], body: bytes) -> bool:
        return 'stripe-signature' in headers
    
    def verify(self, headers: Dict[str, str], raw_body: bytes, config: Dict[str, Any]) -> bool:
        signature = headers.get('stripe-signature')
        if not signature or not config.get('signing_secret'):
            return False
        
        tolerance = config.get('tolerance', 300)  # 5 minutes default
        elements = signature.split(',')
        signatures = []
        timestamp = 0
        
        for element in elements:
            key, value = element.split('=')
            if key == 't':
                timestamp = int(value)
            elif key == 'v1':
                signatures.append(value)
        
        if not timestamp or not signatures:
            return False
        
        if not is_within_tolerance(timestamp, tolerance):
            return False
        
        signed_payload = f"{timestamp}.{raw_body.decode('utf-8')}"
        expected_signature = compute_hmac('sha256', config['signing_secret'], signed_payload)
        
        return any(timing_safe_compare(sig, expected_signature) for sig in signatures)
    
    def extract_event_type(self, headers: Dict[str, str], payload: Any) -> str:
        return payload.get('type') or ''
    
    def parse_payload(self, raw_body: bytes, headers: Dict[str, str]) -> Any:
        return json.loads(raw_body.decode('utf-8'))