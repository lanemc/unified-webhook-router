import pytest
import json
import time
from unittest.mock import patch
from unified_webhook_router.providers.stripe import StripeProvider


class TestStripeProvider:
    
    @pytest.fixture
    def provider(self):
        return StripeProvider()
    
    @pytest.fixture
    def config(self):
        return {'signing_secret': 'whsec_test_secret'}
    
    def test_name(self, provider):
        """Test provider name."""
        assert provider.name == 'stripe'
    
    def test_identify_with_signature(self, provider):
        """Test identification with Stripe signature header."""
        headers = {'stripe-signature': 'sig_123'}
        body = b'{}'
        
        assert provider.identify(headers, body) is True
    
    def test_identify_without_signature(self, provider):
        """Test identification without Stripe signature header."""
        headers = {'x-hub-signature': 'sig_123'}
        body = b'{}'
        
        assert provider.identify(headers, body) is False
    
    def test_identify_empty_headers(self, provider):
        """Test identification with empty headers."""
        headers = {}
        body = b'{}'
        
        assert provider.identify(headers, body) is False
    
    @patch('unified_webhook_router.providers.stripe.is_within_tolerance')
    @patch('unified_webhook_router.providers.stripe.compute_hmac')
    @patch('unified_webhook_router.providers.stripe.timing_safe_compare')
    def test_verify_valid_signature(self, mock_compare, mock_hmac, mock_tolerance, provider, config):
        """Test signature verification with valid signature."""
        timestamp = int(time.time())
        headers = {'stripe-signature': f't={timestamp},v1=valid_signature'}
        raw_body = b'{"test": "payload"}'
        
        mock_tolerance.return_value = True
        mock_hmac.return_value = 'valid_signature'
        mock_compare.return_value = True
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is True
        mock_tolerance.assert_called_once_with(timestamp, 300)
        mock_hmac.assert_called_once_with(
            'sha256',
            'whsec_test_secret',
            f'{timestamp}.{{"test": "payload"}}'
        )
        mock_compare.assert_called_once_with('valid_signature', 'valid_signature')
    
    @patch('unified_webhook_router.providers.stripe.is_within_tolerance')
    @patch('unified_webhook_router.providers.stripe.compute_hmac')
    @patch('unified_webhook_router.providers.stripe.timing_safe_compare')
    def test_verify_invalid_signature(self, mock_compare, mock_hmac, mock_tolerance, provider, config):
        """Test signature verification with invalid signature."""
        timestamp = int(time.time())
        headers = {'stripe-signature': f't={timestamp},v1=invalid_signature'}
        raw_body = b'{"test": "payload"}'
        
        mock_tolerance.return_value = True
        mock_hmac.return_value = 'valid_signature'
        mock_compare.return_value = False
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is False
    
    @patch('unified_webhook_router.providers.stripe.is_within_tolerance')
    def test_verify_expired_timestamp(self, mock_tolerance, provider, config):
        """Test signature verification with expired timestamp."""
        old_timestamp = int(time.time()) - 400
        headers = {'stripe-signature': f't={old_timestamp},v1=valid_signature'}
        raw_body = b'{"test": "payload"}'
        
        mock_tolerance.return_value = False
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is False
        mock_tolerance.assert_called_once_with(old_timestamp, 300)
    
    @patch('unified_webhook_router.providers.stripe.is_within_tolerance')
    @patch('unified_webhook_router.providers.stripe.compute_hmac')
    @patch('unified_webhook_router.providers.stripe.timing_safe_compare')
    def test_verify_custom_tolerance(self, mock_compare, mock_hmac, mock_tolerance, provider):
        """Test signature verification with custom tolerance."""
        timestamp = int(time.time())
        headers = {'stripe-signature': f't={timestamp},v1=valid_signature'}
        raw_body = b'{"test": "payload"}'
        config = {'signing_secret': 'whsec_test_secret', 'tolerance': 600}
        
        mock_tolerance.return_value = True
        mock_hmac.return_value = 'valid_signature'
        mock_compare.return_value = True
        
        provider.verify(headers, raw_body, config)
        
        mock_tolerance.assert_called_once_with(timestamp, 600)
    
    @patch('unified_webhook_router.providers.stripe.is_within_tolerance')
    @patch('unified_webhook_router.providers.stripe.compute_hmac')
    @patch('unified_webhook_router.providers.stripe.timing_safe_compare')
    def test_verify_multiple_signatures(self, mock_compare, mock_hmac, mock_tolerance, provider, config):
        """Test verification with multiple signatures."""
        timestamp = int(time.time())
        headers = {
            'stripe-signature': f't={timestamp},v1=sig1,v1=sig2,v1=valid_signature'
        }
        raw_body = b'{"test": "payload"}'
        
        mock_tolerance.return_value = True
        mock_hmac.return_value = 'valid_signature'
        mock_compare.side_effect = [False, False, True]  # First two fail, third succeeds
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is True
        assert mock_compare.call_count == 3
    
    def test_verify_no_signature_header(self, provider, config):
        """Test verification without signature header."""
        headers = {}
        raw_body = b'{"test": "payload"}'
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is False
    
    def test_verify_no_signing_secret(self, provider):
        """Test verification without signing secret."""
        timestamp = int(time.time())
        headers = {'stripe-signature': f't={timestamp},v1=valid_signature'}
        raw_body = b'{"test": "payload"}'
        config = {}
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is False
    
    def test_verify_malformed_signature(self, provider, config):
        """Test verification with malformed signature."""
        headers = {'stripe-signature': 'malformed_signature'}
        raw_body = b'{"test": "payload"}'
        
        # Should raise ValueError when trying to split
        with pytest.raises(ValueError):
            provider.verify(headers, raw_body, config)
    
    def test_verify_no_timestamp(self, provider, config):
        """Test verification with signature missing timestamp."""
        headers = {'stripe-signature': 'v1=signature_without_timestamp'}
        raw_body = b'{"test": "payload"}'
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is False
    
    def test_verify_no_v1_signatures(self, provider, config):
        """Test verification with no v1 signatures."""
        timestamp = int(time.time())
        headers = {'stripe-signature': f't={timestamp},v0=other_version'}
        raw_body = b'{"test": "payload"}'
        
        result = provider.verify(headers, raw_body, config)
        
        assert result is False
    
    def test_extract_event_type(self, provider):
        """Test event type extraction."""
        payload = {'type': 'payment_intent.succeeded', 'id': 'evt_123'}
        
        result = provider.extract_event_type({}, payload)
        
        assert result == 'payment_intent.succeeded'
    
    def test_extract_event_type_missing(self, provider):
        """Test event type extraction when type is missing."""
        payload = {'id': 'evt_123'}
        
        result = provider.extract_event_type({}, payload)
        
        assert result == ''
    
    def test_extract_event_type_none(self, provider):
        """Test event type extraction when type is None."""
        payload = {'type': None, 'id': 'evt_123'}
        
        result = provider.extract_event_type({}, payload)
        
        # get() with a default returns the default if value is None
        assert result == ''  # This should pass because payload.get('type', '') returns ''
    
    def test_parse_payload(self, provider):
        """Test JSON payload parsing."""
        raw_body = b'{"id": "evt_123", "type": "test"}'
        
        result = provider.parse_payload(raw_body, {})
        
        assert result == {'id': 'evt_123', 'type': 'test'}
    
    def test_parse_payload_invalid_json(self, provider):
        """Test parsing invalid JSON."""
        raw_body = b'invalid json'
        
        with pytest.raises(json.JSONDecodeError):
            provider.parse_payload(raw_body, {})
    
    def test_parse_payload_empty(self, provider):
        """Test parsing empty payload."""
        raw_body = b'{}'
        
        result = provider.parse_payload(raw_body, {})
        
        assert result == {}
    
    def test_parse_payload_complex(self, provider):
        """Test parsing complex nested JSON."""
        complex_payload = {
            'id': 'evt_123',
            'type': 'payment_intent.succeeded',
            'data': {
                'object': {
                    'amount': 1000,
                    'currency': 'usd',
                    'metadata': {
                        'order_id': '12345'
                    }
                }
            }
        }
        raw_body = json.dumps(complex_payload).encode('utf-8')
        
        result = provider.parse_payload(raw_body, {})
        
        assert result == complex_payload
    
    def test_parse_payload_unicode(self, provider):
        """Test parsing payload with unicode characters."""
        unicode_payload = {'message': '🚀 Hello World', 'emoji': '✨'}
        raw_body = json.dumps(unicode_payload).encode('utf-8')
        
        result = provider.parse_payload(raw_body, {})
        
        assert result == unicode_payload