import hmac
import hashlib
import time
from typing import Union


def compute_hmac(algorithm: str, secret: str, message: Union[str, bytes]) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    
    hash_func = getattr(hashlib, algorithm)
    return hmac.new(secret, message, hash_func).hexdigest()


def compute_hmac_base64(algorithm: str, secret: str, message: Union[str, bytes]) -> str:
    import base64
    
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    
    hash_func = getattr(hashlib, algorithm)
    signature = hmac.new(secret, message, hash_func).digest()
    return base64.b64encode(signature).decode('utf-8')


def timing_safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def is_within_tolerance(timestamp: int, tolerance_seconds: int) -> bool:
    now = int(time.time())
    diff = abs(now - timestamp)
    return diff <= tolerance_seconds