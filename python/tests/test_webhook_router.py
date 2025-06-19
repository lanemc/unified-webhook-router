import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from unified_webhook_router.core.webhook_router import WebhookRouter
from unified_webhook_router.types import WebhookEvent, InvalidWebhookError
from unified_webhook_router.utils.logger import NoOpLogger


class TestWebhookRouter:
    
    @pytest.fixture
    def config(self):
        return {
            'stripe': {
                'signing_secret': 'stripe_secret'
            },
            'github': {
                'secret': 'github_secret'
            }
        }
    
    @pytest.fixture
    def router(self, config):
        return WebhookRouter(config, NoOpLogger())
    
    def test_init(self, router, config):
        """Test router initialization."""
        assert router.config == config
        assert 'stripe' in router.providers
        assert 'github' in router.providers
        assert len(router.handlers) == 0
        assert len(router.custom_providers) == 0
    
    def test_init_with_all_providers(self):
        """Test initialization with all built-in providers."""
        config = {
            'stripe': {'signing_secret': 'stripe_secret'},
            'github': {'secret': 'github_secret'},
            'slack': {'signing_secret': 'slack_secret'},
            'twilio': {'auth_token': 'twilio_token'},
            'square': {'signature_key': 'square_key', 'notification_url': 'https://example.com'}
        }
        router = WebhookRouter(config, NoOpLogger())
        
        assert len(router.providers) == 5
        for provider in ['stripe', 'github', 'slack', 'twilio', 'square']:
            assert provider in router.providers
    
    def test_on_as_decorator(self, router):
        """Test using on() as a decorator."""
        @router.on('stripe', 'payment_intent.succeeded')
        def handler(event):
            return 'handled'
        
        assert router.handlers['stripe']['payment_intent.succeeded'] == handler
    
    def test_on_as_method(self, router):
        """Test using on() as a method."""
        def handler(event):
            return 'handled'
        
        router.on('stripe', 'payment_intent.succeeded', handler)
        
        assert router.handlers['stripe']['payment_intent.succeeded'] == handler
    
    def test_register_provider(self, router):
        """Test registering a custom provider."""
        custom_provider = Mock()
        custom_provider.name = 'custom'
        
        router.register_provider(custom_provider)
        
        assert router.custom_providers['custom'] == custom_provider
    
    @pytest.mark.asyncio
    async def test_handle_request_valid_webhook(self, router):
        """Test handling a valid webhook request."""
        # Mock request
        request = Mock()
        request.headers = {'stripe-signature': 'sig_123'}
        request.get_data = Mock(return_value=b'{"id": "evt_123", "type": "payment_intent.succeeded"}')
        
        # Mock provider behavior
        with patch.object(router.providers['stripe'], 'identify', return_value=True), \
             patch.object(router.providers['stripe'], 'verify', return_value=True), \
             patch.object(router.providers['stripe'], 'parse_payload', return_value={
                 'id': 'evt_123',
                 'type': 'payment_intent.succeeded'
             }), \
             patch.object(router.providers['stripe'], 'extract_event_type', return_value='payment_intent.succeeded'):
            
            # Register handler
            handler_called = False
            received_event = None
            
            def handler(event):
                nonlocal handler_called, received_event
                handler_called = True
                received_event = event
                return {'success': True}
            
            router.on('stripe', 'payment_intent.succeeded', handler)
            
            # Handle request
            result = await router.handle_request(request)
            
            assert handler_called
            assert received_event.provider == 'stripe'
            assert received_event.type == 'payment_intent.succeeded'
            assert received_event.id == 'evt_123'
            assert result == {'success': True}
    
    @pytest.mark.asyncio
    async def test_handle_request_async_handler(self, router):
        """Test handling with async handler."""
        request = Mock()
        request.headers = {'stripe-signature': 'sig_123'}
        request.get_data = Mock(return_value=b'{"id": "evt_123"}')
        
        with patch.object(router.providers['stripe'], 'identify', return_value=True), \
             patch.object(router.providers['stripe'], 'verify', return_value=True), \
             patch.object(router.providers['stripe'], 'parse_payload', return_value={'id': 'evt_123'}), \
             patch.object(router.providers['stripe'], 'extract_event_type', return_value='test.event'):
            
            # Register async handler
            handler_called = False
            
            async def async_handler(event):
                nonlocal handler_called
                handler_called = True
                await asyncio.sleep(0.01)  # Simulate async work
                return 'async result'
            
            router.on('stripe', 'test.event', async_handler)
            
            result = await router.handle_request(request)
            
            assert handler_called
            assert result == 'async result'
    
    @pytest.mark.asyncio
    async def test_handle_request_unknown_provider(self, router):
        """Test handling request from unknown provider."""
        request = Mock()
        request.headers = {'unknown-header': 'value'}
        request.get_data = Mock(return_value=b'{}')
        
        with patch.object(router.providers['stripe'], 'identify', return_value=False), \
             patch.object(router.providers['github'], 'identify', return_value=False):
            
            with pytest.raises(InvalidWebhookError, match='Unknown webhook source'):
                await router.handle_request(request)
    
    @pytest.mark.asyncio
    async def test_handle_request_invalid_signature(self, router):
        """Test handling request with invalid signature."""
        request = Mock()
        request.headers = {'stripe-signature': 'invalid_sig'}
        request.get_data = Mock(return_value=b'{}')
        
        with patch.object(router.providers['stripe'], 'identify', return_value=True), \
             patch.object(router.providers['stripe'], 'verify', return_value=False):
            
            with pytest.raises(InvalidWebhookError, match='Invalid signature'):
                await router.handle_request(request)
    
    @pytest.mark.asyncio
    async def test_handle_request_invalid_payload(self, router):
        """Test handling request with invalid payload."""
        request = Mock()
        request.headers = {'stripe-signature': 'sig_123'}
        request.get_data = Mock(return_value=b'invalid json')
        
        with patch.object(router.providers['stripe'], 'identify', return_value=True), \
             patch.object(router.providers['stripe'], 'verify', return_value=True), \
             patch.object(router.providers['stripe'], 'parse_payload', side_effect=ValueError('Invalid JSON')):
            
            with pytest.raises(InvalidWebhookError, match='Invalid payload'):
                await router.handle_request(request)
    
    @pytest.mark.asyncio
    async def test_handle_request_slack_url_verification(self, router):
        """Test handling Slack URL verification challenge."""
        config = {
            'slack': {'signing_secret': 'slack_secret'}
        }
        router = WebhookRouter(config, NoOpLogger())
        
        request = Mock()
        request.headers = {'x-slack-signature': 'sig_123'}
        request.get_data = Mock(return_value=b'{"type": "url_verification", "challenge": "test_challenge"}')
        
        with patch.object(router.providers['slack'], 'identify', return_value=True), \
             patch.object(router.providers['slack'], 'verify', return_value=True), \
             patch.object(router.providers['slack'], 'parse_payload', return_value={
                 'type': 'url_verification',
                 'challenge': 'test_challenge'
             }):
            
            result = await router.handle_request(request)
            
            assert result == 'test_challenge'
    
    @pytest.mark.asyncio
    async def test_handle_request_wildcard_handler(self, router):
        """Test wildcard handler matching."""
        request = Mock()
        request.headers = {'stripe-signature': 'sig_123'}
        request.get_data = Mock(return_value=b'{"id": "evt_123"}')
        
        with patch.object(router.providers['stripe'], 'identify', return_value=True), \
             patch.object(router.providers['stripe'], 'verify', return_value=True), \
             patch.object(router.providers['stripe'], 'parse_payload', return_value={'id': 'evt_123'}), \
             patch.object(router.providers['stripe'], 'extract_event_type', return_value='unknown.event'):
            
            # Register wildcard handler
            wildcard_called = False
            
            def wildcard_handler(event):
                nonlocal wildcard_called
                wildcard_called = True
                return 'wildcard'
            
            router.on('stripe', '*', wildcard_handler)
            
            result = await router.handle_request(request)
            
            assert wildcard_called
            assert result == 'wildcard'
    
    @pytest.mark.asyncio
    async def test_handle_request_no_handler(self, router):
        """Test handling request with no registered handler."""
        request = Mock()
        request.headers = {'stripe-signature': 'sig_123'}
        request.get_data = Mock(return_value=b'{"id": "evt_123"}')
        
        with patch.object(router.providers['stripe'], 'identify', return_value=True), \
             patch.object(router.providers['stripe'], 'verify', return_value=True), \
             patch.object(router.providers['stripe'], 'parse_payload', return_value={'id': 'evt_123'}), \
             patch.object(router.providers['stripe'], 'extract_event_type', return_value='unhandled.event'):
            
            result = await router.handle_request(request)
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_handle_request_custom_provider(self, router):
        """Test handling request from custom provider."""
        # Create custom provider
        custom_provider = Mock()
        custom_provider.name = 'custom'
        custom_provider.identify = Mock(return_value=True)
        custom_provider.verify = Mock(return_value=True)
        custom_provider.parse_payload = Mock(return_value={'custom': 'data'})
        custom_provider.extract_event_type = Mock(return_value='custom.event')
        
        router.register_provider(custom_provider)
        router.config['custom'] = {'key': 'value'}  # Add config for custom provider
        
        # Mock request
        request = Mock()
        request.headers = {'x-custom-header': 'value'}
        request.get_data = Mock(return_value=b'{"custom": "data"}')
        
        # Ensure built-in providers don't match
        with patch.object(router.providers['stripe'], 'identify', return_value=False), \
             patch.object(router.providers['github'], 'identify', return_value=False):
            
            # Register handler
            handler_called = False
            
            def handler(event):
                nonlocal handler_called
                handler_called = True
                return 'custom handled'
            
            router.on('custom', 'custom.event', handler)
            
            result = await router.handle_request(request)
            
            assert handler_called
            assert result == 'custom handled'
            assert custom_provider.identify.called
            assert custom_provider.verify.called
    
    def test_normalize_headers(self, router):
        """Test header normalization."""
        headers = {
            'Content-Type': 'application/json',
            'X-Custom-Header': 'value',
            'UPPERCASE': 'VALUE'
        }
        
        normalized = router._normalize_headers(headers)
        
        assert normalized == {
            'content-type': 'application/json',
            'x-custom-header': 'value',
            'uppercase': 'VALUE'
        }
    
    def test_normalize_headers_with_lists(self, router):
        """Test header normalization with list values."""
        headers = {
            'Single': 'value',
            'Multiple': ['first', 'second']
        }
        
        normalized = router._normalize_headers(headers)
        
        assert normalized == {
            'single': 'value',
            'multiple': 'first'
        }
    
    @pytest.mark.asyncio
    async def test_get_raw_body_flask(self, router):
        """Test getting raw body from Flask request."""
        request = Mock()
        request.get_data = Mock(return_value=b'test body')
        
        body = await router._get_raw_body(request)
        
        assert body == b'test body'
        assert request.get_data.called
    
    @pytest.mark.asyncio
    async def test_get_raw_body_django(self, router):
        """Test getting raw body from Django request."""
        request = Mock()
        request.body = b'django body'
        # Make sure get_data is not present
        del request.get_data
        
        body = await router._get_raw_body(request)
        
        assert body == b'django body'
    
    @pytest.mark.asyncio
    async def test_get_raw_body_async(self, router):
        """Test getting raw body from async framework (AIOHTTP)."""
        request = Mock(spec=['read'])  # Spec with only 'read' method
        
        async def async_read():
            return b'async body'
        
        request.read = async_read
        
        body = await router._get_raw_body(request)
        
        assert body == b'async body'
    
    def test_get_headers_flask(self, router):
        """Test getting headers from Flask request."""
        request = Mock()
        request.headers = {
            'Content-Type': 'application/json',
            'X-Custom': 'value'
        }
        
        headers = router._get_headers(request)
        
        assert headers == {
            'Content-Type': 'application/json',
            'X-Custom': 'value'
        }
    
    def test_get_headers_django(self, router):
        """Test getting headers from Django request."""
        request = Mock(spec=[])  # Empty spec to ensure no auto-generated attributes
        request.META = {
            'HTTP_CONTENT_TYPE': 'application/json',
            'HTTP_X_CUSTOM': 'value',
            'CONTENT_TYPE': 'application/json',
            'CONTENT_LENGTH': '100',
            'REMOTE_ADDR': '127.0.0.1'  # Should be ignored
        }
        
        headers = router._get_headers(request)
        
        assert headers == {
            'content-type': 'application/json',
            'x-custom': 'value',
            'content-length': '100'
        }
    
    def test_extract_event_id(self, router):
        """Test event ID extraction for different providers."""
        # Stripe
        stripe_id = router._extract_event_id('stripe', {}, {'id': 'evt_123'})
        assert stripe_id == 'evt_123'
        
        # GitHub
        github_id = router._extract_event_id('github', {'x-github-delivery': 'gh_123'}, {})
        assert github_id == 'gh_123'
        
        # Slack (direct event_id)
        slack_id = router._extract_event_id('slack', {}, {'event_id': 'slack_123'})
        assert slack_id == 'slack_123'
        
        # Slack (nested event)
        slack_nested_id = router._extract_event_id('slack', {}, {'event': {'event_id': 'slack_nested'}})
        assert slack_nested_id == 'slack_nested'
        
        # Unknown provider
        unknown_id = router._extract_event_id('unknown', {}, {})
        assert unknown_id is None