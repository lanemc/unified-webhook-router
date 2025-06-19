import json
from typing import Dict, Any
from urllib.parse import parse_qs
from ..types import WebhookProvider
from ..utils import compute_hmac, timing_safe_compare
import hashlib
import base64


class TwilioProvider(WebhookProvider):
    @property
    def name(self) -> str:
        return 'twilio'
    
    def identify(self, headers: Dict[str, str], body: bytes) -> bool:
        return 'x-twilio-signature' in headers
    
    def verify(self, headers: Dict[str, str], raw_body: bytes, config: Dict[str, Any]) -> bool:
        signature = headers.get('x-twilio-signature')
        if not signature or not config.get('auth_token'):
            return False
        
        # For Twilio, we need the full URL
        # Try to reconstruct from headers or use config
        proto = headers.get('x-forwarded-proto', 'https')
        host = headers.get('host', '')
        path = headers.get('x-original-url', '')
        url = config.get('webhook_url', f"{proto}://{host}{path}")
        
        # Parse the body to get parameters
        content_type = headers.get('content-type', '')
        params = {}
        
        if 'application/x-www-form-urlencoded' in content_type:
            parsed = parse_qs(raw_body.decode('utf-8'))
            params = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        elif 'application/json' in content_type:
            params = json.loads(raw_body.decode('utf-8'))
        
        # Sort parameters alphabetically and concatenate
        sorted_keys = sorted(params.keys())
        data = url
        
        for key in sorted_keys:
            data += key + str(params[key])
        
        # Compute HMAC-SHA1
        auth_token = config['auth_token']
        if isinstance(auth_token, str):
            auth_token = auth_token.encode('utf-8')
        
        signature_bytes = hashlib.sha1(auth_token + data.encode('utf-8')).digest()
        expected_signature = base64.b64encode(signature_bytes).decode('utf-8')
        
        return timing_safe_compare(signature, expected_signature)
    
    def extract_event_type(self, headers: Dict[str, str], payload: Any) -> str:
        # Twilio doesn't have a specific event type field
        if payload.get('MessageStatus'):
            return 'message.status'
        elif payload.get('CallStatus'):
            return 'call.status'
        elif payload.get('Body') and payload.get('From'):
            return 'message.received'
        return 'webhook'
    
    def parse_payload(self, raw_body: bytes, headers: Dict[str, str]) -> Any:
        content_type = headers.get('content-type', '')
        
        if 'application/x-www-form-urlencoded' in content_type:
            parsed = parse_qs(raw_body.decode('utf-8'))
            payload = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            return payload
        else:
            return json.loads(raw_body.decode('utf-8'))