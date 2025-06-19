import logging
import sys
from enum import IntEnum
from typing import Optional, Dict, Any, Union
from datetime import datetime


class LogLevel(IntEnum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARN = logging.WARNING
    ERROR = logging.ERROR
    NONE = logging.CRITICAL + 1


class WebhookLogger:
    """Logger wrapper for webhook router with structured logging support."""
    
    def __init__(self, name: str = 'webhook-router', level: LogLevel = LogLevel.INFO):
        self.logger = logging.getLogger(name)
        self.current_level = level
        self.set_level(level)
        
        # Configure handler if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def set_level(self, level: LogLevel) -> None:
        """Set the logging level."""
        self.current_level = level
        self.logger.setLevel(level)
    
    def debug(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message."""
        if self.current_level <= LogLevel.DEBUG:
            if context is not None:
                message = f"{message} - {context}"
            self.logger.debug(message)
    
    def info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log info message."""
        if self.current_level <= LogLevel.INFO:
            if context is not None:
                message = f"{message} - {context}"
            self.logger.info(message)
    
    def warn(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message."""
        if self.current_level <= LogLevel.WARN:
            if context is not None:
                message = f"{message} - {context}"
            self.logger.warning(message)
    
    def error(self, message: str, error: Optional[Union[Exception, Dict[str, Any]]] = None, 
              context: Optional[Dict[str, Any]] = None) -> None:
        """Log error message."""
        if self.current_level <= LogLevel.ERROR:
            parts = [message]
            
            if isinstance(error, Exception):
                parts.append(f"Error: {type(error).__name__}: {str(error)}")
            elif error:
                parts.append(f"Error: {error}")
            
            if context:
                parts.append(f"Context: {context}")
            
            self.logger.error(" - ".join(parts))


class NoOpLogger:
    """No-operation logger for testing or disabling logging."""
    
    def set_level(self, level: LogLevel) -> None:
        pass
    
    def debug(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        pass
    
    def info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        pass
    
    def warn(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        pass
    
    def error(self, message: str, error: Optional[Union[Exception, Dict[str, Any]]] = None,
              context: Optional[Dict[str, Any]] = None) -> None:
        pass


# Default logger instance
_default_logger = WebhookLogger()


def get_default_logger():
    """Get the default logger instance."""
    return _default_logger


def set_default_logger(logger: Union[WebhookLogger, NoOpLogger]) -> None:
    """Set the default logger instance."""
    global _default_logger
    _default_logger = logger