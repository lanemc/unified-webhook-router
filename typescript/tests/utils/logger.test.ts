import { ConsoleLogger, NoOpLogger, LogLevel, setDefaultLogger, getDefaultLogger } from '../../src/utils/logger';

describe('Logger Implementations', () => {
  let consoleSpies: {
    debug: jest.SpyInstance;
    info: jest.SpyInstance;
    warn: jest.SpyInstance;
    error: jest.SpyInstance;
  };

  beforeEach(() => {
    // Mock console methods
    consoleSpies = {
      debug: jest.spyOn(console, 'debug').mockImplementation(),
      info: jest.spyOn(console, 'info').mockImplementation(),
      warn: jest.spyOn(console, 'warn').mockImplementation(),
      error: jest.spyOn(console, 'error').mockImplementation()
    };
  });

  afterEach(() => {
    // Restore console methods
    Object.values(consoleSpies).forEach(spy => spy.mockRestore());
  });

  describe('ConsoleLogger', () => {
    describe('Log Level Filtering', () => {
      it('should respect log level for debug messages', () => {
        const logger = new ConsoleLogger(LogLevel.INFO);
        logger.debug('debug message');
        expect(consoleSpies.debug).not.toHaveBeenCalled();

        logger.setLevel(LogLevel.DEBUG);
        logger.debug('debug message');
        expect(consoleSpies.debug).toHaveBeenCalled();
      });

      it('should respect log level for info messages', () => {
        const logger = new ConsoleLogger(LogLevel.WARN);
        logger.info('info message');
        expect(consoleSpies.info).not.toHaveBeenCalled();

        logger.setLevel(LogLevel.INFO);
        logger.info('info message');
        expect(consoleSpies.info).toHaveBeenCalled();
      });

      it('should respect log level for warn messages', () => {
        const logger = new ConsoleLogger(LogLevel.ERROR);
        logger.warn('warn message');
        expect(consoleSpies.warn).not.toHaveBeenCalled();

        logger.setLevel(LogLevel.WARN);
        logger.warn('warn message');
        expect(consoleSpies.warn).toHaveBeenCalled();
      });

      it('should respect log level for error messages', () => {
        const logger = new ConsoleLogger(LogLevel.NONE);
        logger.error('error message');
        expect(consoleSpies.error).not.toHaveBeenCalled();

        logger.setLevel(LogLevel.ERROR);
        logger.error('error message');
        expect(consoleSpies.error).toHaveBeenCalled();
      });
    });

    describe('Message Formatting', () => {
      it('should format debug messages with timestamp and context', () => {
        const logger = new ConsoleLogger(LogLevel.DEBUG);
        const context = { userId: '123', action: 'webhook_received' };
        
        logger.debug('Processing webhook', context);
        
        expect(consoleSpies.debug).toHaveBeenCalledWith(
          expect.stringMatching(/\[DEBUG\] \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z - Processing webhook/),
          context
        );
      });

      it('should handle empty context gracefully', () => {
        const logger = new ConsoleLogger(LogLevel.DEBUG);
        
        logger.debug('Simple message');
        
        expect(consoleSpies.debug).toHaveBeenCalledWith(
          expect.stringMatching(/\[DEBUG\].*Simple message/),
          ''
        );
      });

      it('should format error messages with Error objects', () => {
        const logger = new ConsoleLogger(LogLevel.ERROR);
        const error = new Error('Test error');
        const context = { operation: 'signature_verification' };
        
        logger.error('Operation failed', error, context);
        
        expect(consoleSpies.error).toHaveBeenCalledWith(
          expect.stringMatching(/\[ERROR\].*Operation failed/),
          error,
          context
        );
      });

      it('should format error messages with error context objects', () => {
        const logger = new ConsoleLogger(LogLevel.ERROR);
        const errorContext = { code: 'INVALID_SIGNATURE', provider: 'stripe' };
        
        logger.error('Webhook verification failed', errorContext);
        
        expect(consoleSpies.error).toHaveBeenCalledWith(
          expect.stringMatching(/\[ERROR\].*Webhook verification failed/),
          errorContext,
          ''
        );
      });
    });

    describe('Edge Cases', () => {
      it('should handle undefined and null contexts', () => {
        const logger = new ConsoleLogger(LogLevel.DEBUG);
        
        logger.debug('Message with undefined', undefined);
        logger.info('Message with null', null as any);
        
        expect(consoleSpies.debug).toHaveBeenCalledWith(
          expect.stringMatching(/Message with undefined/),
          ''
        );
        expect(consoleSpies.info).toHaveBeenCalledWith(
          expect.stringMatching(/Message with null/),
          ''
        );
      });

      it('should handle very large context objects', () => {
        const logger = new ConsoleLogger(LogLevel.DEBUG);
        const largeContext = {
          data: Array(1000).fill(0).map((_, i) => ({ id: i, value: `item_${i}` }))
        };
        
        logger.debug('Large context', largeContext);
        
        expect(consoleSpies.debug).toHaveBeenCalled();
      });

      it('should handle circular references in context', () => {
        const logger = new ConsoleLogger(LogLevel.DEBUG);
        const circularContext: any = { name: 'test' };
        circularContext.self = circularContext;
        
        // Should not throw
        expect(() => logger.debug('Circular context', circularContext)).not.toThrow();
      });
    });
  });

  describe('NoOpLogger', () => {
    it('should not output anything', () => {
      const logger = new NoOpLogger();
      
      logger.debug('debug message', { test: true });
      logger.info('info message', { test: true });
      logger.warn('warn message', { test: true });
      logger.error('error message', new Error('test'), { test: true });
      logger.setLevel(LogLevel.DEBUG);
      
      expect(consoleSpies.debug).not.toHaveBeenCalled();
      expect(consoleSpies.info).not.toHaveBeenCalled();
      expect(consoleSpies.warn).not.toHaveBeenCalled();
      expect(consoleSpies.error).not.toHaveBeenCalled();
    });
  });

  describe('Default Logger', () => {
    it('should provide a default ConsoleLogger instance', () => {
      const defaultLogger = getDefaultLogger();
      expect(defaultLogger).toBeInstanceOf(ConsoleLogger);
    });

    it('should allow setting a custom default logger', () => {
      const customLogger = new NoOpLogger();
      setDefaultLogger(customLogger);
      
      const defaultLogger = getDefaultLogger();
      expect(defaultLogger).toBe(customLogger);
      
      // Restore default
      setDefaultLogger(new ConsoleLogger());
    });
  });

  describe('Performance', () => {
    it('should not log when level is higher than message level', () => {
      const logger = new ConsoleLogger(LogLevel.ERROR);
      const startTime = Date.now();
      
      // These should return immediately without formatting
      for (let i = 0; i < 10000; i++) {
        logger.debug('debug message', { index: i });
        logger.info('info message', { index: i });
        logger.warn('warn message', { index: i });
      }
      
      const endTime = Date.now();
      expect(endTime - startTime).toBeLessThan(100); // Should be very fast
      expect(consoleSpies.debug).not.toHaveBeenCalled();
      expect(consoleSpies.info).not.toHaveBeenCalled();
      expect(consoleSpies.warn).not.toHaveBeenCalled();
    });
  });
});

describe('WebhookRouter Logger Integration', () => {
  // These tests will verify logger integration with WebhookRouter
  // They will be implemented after the logger tests pass
});