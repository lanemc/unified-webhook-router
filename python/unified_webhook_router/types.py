from typing import Dict, Any, Optional, Callable, Union, Awaitable
from dataclasses import dataclass
from datetime import datetime
from abc import ABC, abstractmethod


@dataclass
class WebhookEvent:
    provider: str
    type: str
    payload: Any
    raw_headers: Dict[str, str]
    raw_body: str
    id: Optional[str] = None
    received_at: Optional[datetime] = None


WebhookHandler = Callable[[WebhookEvent], Union[None, Any, Awaitable[Union[None, Any]]]]


class WebhookProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @abstractmethod
    def identify(self, headers: Dict[str, str], body: bytes) -> bool:
        pass
    
    @abstractmethod
    def verify(self, headers: Dict[str, str], raw_body: bytes, config: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def extract_event_type(self, headers: Dict[str, str], payload: Any) -> str:
        pass
    
    @abstractmethod
    def parse_payload(self, raw_body: bytes, headers: Dict[str, str]) -> Any:
        pass


class InvalidWebhookError(Exception):
    pass