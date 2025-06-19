import json
from typing import Dict, Any
from ..types import WebhookProvider
from ..utils import compute_hmac, timing_safe_compare


class GitHubProvider(WebhookProvider):
    @property
    def name(self) -> str:
        return 'github'
    
    def identify(self, headers: Dict[str, str], body: bytes) -> bool:
        return 'x-hub-signature' in headers or 'x-hub-signature-256' in headers
    
    def verify(self, headers: Dict[str, str], raw_body: bytes, config: Dict[str, Any]) -> bool:
        if not config.get('secret'):
            return False
        
        algorithm = config.get('algorithm', 'sha256')
        signature_header = 'x-hub-signature-256' if algorithm == 'sha256' else 'x-hub-signature'
        signature = headers.get(signature_header)
        
        if not signature:
            return False
        
        expected_signature = f"{algorithm}={compute_hmac(algorithm, config['secret'], raw_body)}"
        
        return timing_safe_compare(signature, expected_signature)
    
    def extract_event_type(self, headers: Dict[str, str], payload: Any) -> str:
        return headers.get('x-github-event', '')
    
    def parse_payload(self, raw_body: bytes, headers: Dict[str, str]) -> Any:
        return json.loads(raw_body.decode('utf-8'))