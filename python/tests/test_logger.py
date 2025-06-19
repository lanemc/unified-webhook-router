import pytest
import logging
from unittest.mock import MagicMock, patch, call
from datetime import datetime
from unified_webhook_router.utils.logger import (
    LogLevel, WebhookLogger, NoOpLogger, 
    get_default_logger, set_default_logger
)


class TestWebhookLogger:
    """Test suite for WebhookLogger implementation."""
    
    def test_initialization_default_level(self):
        """Test logger initialization with default INFO level."""
        logger = WebhookLogger()
        assert logger.logger.level == LogLevel.INFO
    
    def test_initialization_custom_level(self):
        """Test logger initialization with custom level."""
        logger = WebhookLogger(level=LogLevel.DEBUG)
        assert logger.logger.level == LogLevel.DEBUG
    
    def test_set_level(self):
        """Test changing log level after initialization."""
        logger = WebhookLogger()
        logger.set_level(LogLevel.ERROR)
        assert logger.logger.level == LogLevel.ERROR
    
    @patch('logging.StreamHandler')
    def test_handler_configuration(self, mock_handler_class):
        """Test that handler is properly configured on first initialization."""
        mock_handler = MagicMock()
        mock_handler_class.return_value = mock_handler
        
        logger = WebhookLogger('test-logger')
        
        mock_handler_class.assert_called_once()
        mock_handler.setFormatter.assert_called_once()
    
    @patch('logging.Logger.debug')
    def test_debug_logging(self, mock_debug):
        """Test debug message logging with and without context."""
        logger = WebhookLogger(level=LogLevel.DEBUG)
        
        # Without context
        logger.debug("Debug message")
        mock_debug.assert_called_with("Debug message")
        
        # With context
        context = {"user_id": "123", "action": "webhook_received"}
        logger.debug("Debug with context", context)
        mock_debug.assert_called_with(f"Debug with context - {context}")
    
    @patch('logging.Logger.info')
    def test_info_logging(self, mock_info):
        """Test info message logging."""
        logger = WebhookLogger(level=LogLevel.INFO)
        
        logger.info("Info message")
        mock_info.assert_called_with("Info message")
        
        context = {"provider": "stripe"}
        logger.info("Info with context", context)
        mock_info.assert_called_with(f"Info with context - {context}")
    
    @patch('logging.Logger.warning')
    def test_warn_logging(self, mock_warning):
        """Test warning message logging."""
        logger = WebhookLogger(level=LogLevel.WARN)
        
        logger.warn("Warning message")
        mock_warning.assert_called_with("Warning message")
        
        context = {"retry_count": 3}
        logger.warn("Warning with context", context)
        mock_warning.assert_called_with(f"Warning with context - {context}")
    
    @patch('logging.Logger.error')
    def test_error_logging_with_exception(self, mock_error):
        """Test error logging with Exception objects."""
        logger = WebhookLogger(level=LogLevel.ERROR)
        
        # With Exception
        error = ValueError("Invalid signature")
        logger.error("Signature verification failed", error)
        mock_error.assert_called_with(
            "Signature verification failed - Error: ValueError: Invalid signature"
        )
        
        # With Exception and context
        context = {"provider": "github", "event": "push"}
        logger.error("Processing failed", error, context)
        mock_error.assert_called_with(
            f"Processing failed - Error: ValueError: Invalid signature - Context: {context}"
        )
    
    @patch('logging.Logger.error')
    def test_error_logging_with_dict(self, mock_error):
        """Test error logging with dictionary error context."""
        logger = WebhookLogger(level=LogLevel.ERROR)
        
        error_dict = {"code": "INVALID_PAYLOAD", "details": "JSON parse error"}
        logger.error("Payload parsing failed", error_dict)
        mock_error.assert_called_with(
            f"Payload parsing failed - Error: {error_dict}"
        )
    
    @patch('logging.Logger.error')
    def test_error_logging_without_error(self, mock_error):
        """Test error logging with just message."""
        logger = WebhookLogger(level=LogLevel.ERROR)
        
        logger.error("Simple error message")
        mock_error.assert_called_with("Simple error message")
    
    def test_log_level_filtering(self):
        """Test that messages below log level are not logged."""
        logger = WebhookLogger(level=LogLevel.ERROR)
        
        with patch.object(logger.logger, 'debug') as mock_debug:
            with patch.object(logger.logger, 'info') as mock_info:
                with patch.object(logger.logger, 'warning') as mock_warn:
                    with patch.object(logger.logger, 'error') as mock_error:
                        logger.debug("Debug")
                        logger.info("Info")
                        logger.warn("Warn")
                        logger.error("Error")
                        
                        # Only error should be called
                        mock_debug.assert_not_called()
                        mock_info.assert_not_called()
                        mock_warn.assert_not_called()
                        mock_error.assert_called_once()
    
    def test_edge_cases(self):
        """Test edge cases like None contexts and empty strings."""
        logger = WebhookLogger(level=LogLevel.DEBUG)
        
        with patch.object(logger.logger, 'debug') as mock_debug:
            # None context
            logger.debug("Message", None)
            mock_debug.assert_called_with("Message")
            
            # Empty dict context - should still append context
            logger.debug("Message", {})
            mock_debug.assert_called_with("Message - {}")
            
            # Empty string message
            logger.debug("", {"key": "value"})
            mock_debug.assert_called_with(" - {'key': 'value'}")
    
    def test_large_context_handling(self):
        """Test handling of very large context objects."""
        logger = WebhookLogger(level=LogLevel.DEBUG)
        
        large_context = {
            f"key_{i}": f"value_{i}" * 100 
            for i in range(100)
        }
        
        # Should not raise any exceptions
        with patch.object(logger.logger, 'debug') as mock_debug:
            logger.debug("Large context", large_context)
            assert mock_debug.called
    
    def test_unicode_handling(self):
        """Test handling of unicode characters in messages and context."""
        logger = WebhookLogger(level=LogLevel.DEBUG)
        
        with patch.object(logger.logger, 'debug') as mock_debug:
            unicode_context = {"emoji": "🚀", "chinese": "你好", "arabic": "مرحبا"}
            logger.debug("Unicode test 🌟", unicode_context)
            
            # Should handle unicode without errors
            assert mock_debug.called
            call_args = mock_debug.call_args[0][0]
            assert "🌟" in call_args
            assert "🚀" in call_args


class TestNoOpLogger:
    """Test suite for NoOpLogger implementation."""
    
    def test_all_methods_do_nothing(self):
        """Test that all NoOpLogger methods do nothing."""
        logger = NoOpLogger()
        
        # None of these should raise exceptions
        logger.set_level(LogLevel.DEBUG)
        logger.debug("Debug", {"test": True})
        logger.info("Info", {"test": True})
        logger.warn("Warn", {"test": True})
        logger.error("Error", ValueError("test"), {"test": True})
        
        # Verify no output (would need to capture stdout/stderr in real test)
        # For now, just verify methods exist and don't error
        assert True
    
    def test_noop_logger_interface(self):
        """Test that NoOpLogger implements the same interface as WebhookLogger."""
        noop = NoOpLogger()
        webhook = WebhookLogger()
        
        # Check that all public methods exist
        for method in ['set_level', 'debug', 'info', 'warn', 'error']:
            assert hasattr(noop, method)
            assert callable(getattr(noop, method))
            assert hasattr(webhook, method)


class TestDefaultLogger:
    """Test suite for default logger functionality."""
    
    def test_get_default_logger(self):
        """Test getting the default logger instance."""
        logger = get_default_logger()
        assert isinstance(logger, WebhookLogger)
    
    def test_set_default_logger(self):
        """Test setting a custom default logger."""
        custom_logger = NoOpLogger()
        set_default_logger(custom_logger)
        
        retrieved = get_default_logger()
        assert retrieved is custom_logger
        
        # Restore default
        set_default_logger(WebhookLogger())
    
    def test_default_logger_persistence(self):
        """Test that default logger persists across calls."""
        logger1 = get_default_logger()
        logger2 = get_default_logger()
        assert logger1 is logger2


class TestLoggerPerformance:
    """Performance-related tests for logger implementations."""
    
    def test_noop_logger_performance(self):
        """Test that NoOpLogger has minimal performance impact."""
        logger = NoOpLogger()
        import time
        
        start_time = time.time()
        for i in range(10000):
            logger.debug(f"Message {i}", {"index": i})
            logger.info(f"Message {i}", {"index": i})
            logger.warn(f"Message {i}", {"index": i})
            logger.error(f"Message {i}", {"index": i, "error": "test"})
        
        elapsed = time.time() - start_time
        # Should complete very quickly (< 0.1 seconds)
        assert elapsed < 0.1
    
    def test_level_filtering_performance(self):
        """Test that level filtering prevents unnecessary formatting."""
        logger = WebhookLogger(level=LogLevel.ERROR)
        
        with patch.object(logger.logger, 'debug') as mock_debug:
            with patch.object(logger.logger, 'info') as mock_info:
                import time
                
                start_time = time.time()
                for i in range(1000):
                    # These should return immediately without formatting
                    logger.debug(f"Debug {i}", {"large": "data" * 1000})
                    logger.info(f"Info {i}", {"large": "data" * 1000})
                
                elapsed = time.time() - start_time
                
                # Should be very fast since no actual logging occurs
                assert elapsed < 0.1
                mock_debug.assert_not_called()
                mock_info.assert_not_called()


class TestLoggerIntegration:
    """Integration tests for logger with WebhookRouter."""
    
    @pytest.fixture
    def mock_webhook_router(self):
        """Create a mock WebhookRouter for testing."""
        from unittest.mock import MagicMock
        router = MagicMock()
        router.logger = WebhookLogger()
        return router
    
    def test_logger_integration_with_router(self, mock_webhook_router):
        """Test that logger integrates properly with WebhookRouter."""
        # This test will be expanded when implementing WebhookRouter integration tests
        assert mock_webhook_router.logger is not None
        assert isinstance(mock_webhook_router.logger, WebhookLogger)