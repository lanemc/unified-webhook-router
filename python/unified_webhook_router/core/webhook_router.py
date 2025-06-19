import asyncio
import inspect
from datetime import datetime
from typing import Dict, Any, Optional, Callable, Union
from ..types import WebhookEvent, WebhookHandler, WebhookProvider, InvalidWebhookError
from ..providers import (
    StripeProvider,
    GitHubProvider,
    SlackProvider,
    TwilioProvider,
    SquareProvider
)
from ..utils.logger import WebhookLogger, NoOpLogger, get_default_logger


class WebhookRouter:
    def __init__(self, config: Dict[str, Any], logger: Optional[Union[WebhookLogger, NoOpLogger]] = None):
        self.config = config
        self.providers: Dict[str, WebhookProvider] = {}
        self.handlers: Dict[str, Dict[str, WebhookHandler]] = {}
        self.custom_providers: Dict[str, WebhookProvider] = {}
        self.logger = logger or get_default_logger()
        self._initialize_providers()
    
    def _initialize_providers(self):
        # Register built-in providers
        if 'stripe' in self.config:
            self.providers['stripe'] = StripeProvider()
        if 'github' in self.config:
            self.providers['github'] = GitHubProvider()
        if 'slack' in self.config:
            self.providers['slack'] = SlackProvider()
        if 'twilio' in self.config:
            self.providers['twilio'] = TwilioProvider()
        if 'square' in self.config:
            self.providers['square'] = SquareProvider()
    
    def on(self, provider: str, event_type: str, handler: Optional[WebhookHandler] = None):
        """Register a webhook handler. Can be used as a decorator or method."""
        def decorator(handler_func: WebhookHandler) -> WebhookHandler:
            if provider not in self.handlers:
                self.handlers[provider] = {}
            self.handlers[provider][event_type] = handler_func
            return handler_func
        
        if handler is None:
            # Used as decorator
            return decorator
        else:
            # Used as method
            decorator(handler)
    
    def register_provider(self, provider: WebhookProvider):
        """Register a custom webhook provider."""
        self.custom_providers[provider.name] = provider
    
    async def handle_request(self, request) -> Optional[Any]:
        """Handle a webhook request. Framework-agnostic method."""
        # Extract headers and body
        headers = self._normalize_headers(self._get_headers(request))
        raw_body = await self._get_raw_body(request)
        
        self.logger.debug('Processing webhook request', {
            'headers': ', '.join(headers.keys()),
            'body_size': len(raw_body)
        })
        
        # Identify provider
        provider = self._identify_provider(headers, raw_body)
        if not provider:
            self.logger.warn('Unknown webhook source', {'headers': headers})
            raise InvalidWebhookError('Unknown webhook source')
        
        self.logger.debug(f'Identified provider: {provider.name}')
        
        # Get provider config
        provider_config = self.config.get(provider.name)
        if not provider_config:
            raise InvalidWebhookError(f'Provider {provider.name} not configured')
        
        # Verify signature
        if not provider.verify(headers, raw_body, provider_config):
            self.logger.warn(f'Invalid signature for {provider.name} webhook')
            raise InvalidWebhookError('Invalid signature')
        
        self.logger.debug(f'Signature verified for {provider.name}')
        
        # Parse payload
        try:
            payload = provider.parse_payload(raw_body, headers)
        except Exception as e:
            raise InvalidWebhookError(f'Invalid payload: {str(e)}')
        
        # Handle special cases
        if provider.name == 'slack' and payload.get('type') == 'url_verification':
            return payload.get('challenge')
        
        # Extract event type
        event_type = provider.extract_event_type(headers, payload)
        
        # Create event object
        event = WebhookEvent(
            provider=provider.name,
            type=event_type,
            id=self._extract_event_id(provider.name, headers, payload),
            payload=payload,
            raw_headers=headers,
            raw_body=raw_body.decode('utf-8'),
            received_at=datetime.now()
        )
        
        # Find and execute handler
        handler = self._find_handler(provider.name, event_type)
        
        if handler:
            try:
                self.logger.info(f'Executing handler for {provider.name}/{event_type}', {
                    'event_id': event.id
                })
                
                # Execute handler
                if inspect.iscoroutinefunction(handler):
                    result = await handler(event)
                else:
                    result = handler(event)
                
                self.logger.info(f'Successfully processed {provider.name}/{event_type}', {
                    'event_id': event.id
                })
                
                return result
            except Exception as e:
                self.logger.error(f'Handler error for {provider.name}/{event_type}', e, {
                    'provider': provider.name,
                    'event_type': event_type,
                    'event_id': event.id
                })
                raise
        else:
            self.logger.debug(f'No handler registered for {provider.name}/{event_type}')
        
        # No handler found, but webhook is valid
        return None
    
    def _normalize_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        """Normalize headers to lowercase string keys."""
        normalized = {}
        for key, value in headers.items():
            normalized[key.lower()] = str(value) if not isinstance(value, list) else str(value[0])
        return normalized
    
    def _get_headers(self, request) -> Dict[str, Any]:
        """Extract headers from various request objects."""
        # Flask/Werkzeug
        if hasattr(request, 'headers'):
            return dict(request.headers)
        # Django
        elif hasattr(request, 'META'):
            headers = {}
            for key, value in request.META.items():
                if key.startswith('HTTP_'):
                    header_name = key[5:].replace('_', '-').lower()
                    headers[header_name] = value
                elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
                    headers[key.replace('_', '-').lower()] = value
            return headers
        # FastAPI/Starlette
        elif hasattr(request, 'headers'):
            return dict(request.headers)
        else:
            raise ValueError('Unable to extract headers from request object')
    
    async def _get_raw_body(self, request) -> bytes:
        """Extract raw body from various request objects."""
        # Flask/Werkzeug
        if hasattr(request, 'get_data'):
            return request.get_data()
        # Django
        elif hasattr(request, 'body'):
            return request.body
        # FastAPI/Starlette (async)
        elif hasattr(request, 'body') and inspect.iscoroutinefunction(request.body):
            return await request.body()
        # AIOHTTP
        elif hasattr(request, 'read'):
            return await request.read()
        else:
            raise ValueError('Unable to extract body from request object')
    
    def _identify_provider(self, headers: Dict[str, str], body: bytes) -> Optional[WebhookProvider]:
        """Identify which provider sent the webhook."""
        # Check built-in providers first
        for provider in self.providers.values():
            if provider.identify(headers, body):
                return provider
        
        # Check custom providers
        for provider in self.custom_providers.values():
            if provider.identify(headers, body):
                return provider
        
        return None
    
    def _find_handler(self, provider: str, event_type: str) -> Optional[WebhookHandler]:
        """Find the appropriate handler for an event."""
        provider_handlers = self.handlers.get(provider)
        if not provider_handlers:
            return None
        
        # Check for exact match
        if event_type in provider_handlers:
            return provider_handlers[event_type]
        
        # Check for wildcard
        if '*' in provider_handlers:
            return provider_handlers['*']
        
        return None
    
    def _extract_event_id(self, provider: str, headers: Dict[str, str], payload: Any) -> Optional[str]:
        """Extract event ID if available."""
        if provider == 'stripe':
            return payload.get('id')
        elif provider == 'github':
            return headers.get('x-github-delivery')
        elif provider == 'slack':
            return payload.get('event_id') or (payload.get('event', {}).get('event_id'))
        return None