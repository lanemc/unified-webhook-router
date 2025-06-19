import { WebhookRouter } from '../../src/core/WebhookRouter';
import { ConsoleLogger, NoOpLogger, LogLevel } from '../../src/utils/logger';
import { WebhookRouterConfig } from '../../src/types';
import { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';

// Mock providers
jest.mock('../../src/providers', () => ({
  StripeProvider: {
    name: 'stripe',
    identify: jest.fn(),
    verify: jest.fn(),
    parsePayload: jest.fn(),
    extractEventType: jest.fn()
  },
  GitHubProvider: {
    name: 'github',
    identify: jest.fn(),
    verify: jest.fn(),
    parsePayload: jest.fn(),
    extractEventType: jest.fn()
  }
}));

// Helper functions
function createMockRequest(headers: Record<string, string>, body: string): IncomingMessage {
  const req = new EventEmitter() as IncomingMessage;
  req.headers = headers;
  
  setImmediate(() => {
    req.emit('data', Buffer.from(body));
    req.emit('end');
  });
  
  return req;
}

function createMockResponse(): ServerResponse & { _statusCode?: number; _data?: string } {
  const res = new EventEmitter() as ServerResponse & { _statusCode?: number; _data?: string };
  res.statusCode = 200;
  res.end = jest.fn((data?: any) => {
    res._data = data;
    res._statusCode = res.statusCode;
  }) as any;
  return res;
}

describe('WebhookRouter Logger Integration', () => {
  let loggerSpy: {
    debug: jest.SpyInstance;
    info: jest.SpyInstance;
    warn: jest.SpyInstance;
    error: jest.SpyInstance;
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Logger Injection', () => {
    it('should accept custom logger in constructor', () => {
      const customLogger = new ConsoleLogger(LogLevel.DEBUG);
      const config: WebhookRouterConfig = {
        stripe: { signingSecret: 'test_secret' }
      };
      
      const router = new WebhookRouter(config, customLogger);
      expect(router).toBeInstanceOf(WebhookRouter);
    });

    it('should use default logger when none provided', () => {
      const config: WebhookRouterConfig = {
        stripe: { signingSecret: 'test_secret' }
      };
      
      const router = new WebhookRouter(config);
      expect(router).toBeInstanceOf(WebhookRouter);
    });
  });

  describe('Request Lifecycle Logging', () => {
    let router: WebhookRouter;
    let logger: ConsoleLogger;
    let config: WebhookRouterConfig;

    beforeEach(() => {
      logger = new ConsoleLogger(LogLevel.DEBUG);
      loggerSpy = {
        debug: jest.spyOn(logger, 'debug').mockImplementation(),
        info: jest.spyOn(logger, 'info').mockImplementation(),
        warn: jest.spyOn(logger, 'warn').mockImplementation(),
        error: jest.spyOn(logger, 'error').mockImplementation()
      };
      
      config = {
        stripe: { signingSecret: 'stripe_secret' }
      };
      
      router = new WebhookRouter(config, logger);
    });

    it('should log webhook request processing', async () => {
      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('payment_intent.succeeded');

      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      // Verify initial request logging
      expect(loggerSpy.debug).toHaveBeenCalledWith(
        'Processing webhook request',
        expect.objectContaining({
          headers: expect.any(String),
          bodySize: expect.any(Number)
        })
      );

      // Verify provider identification logging
      expect(loggerSpy.debug).toHaveBeenCalledWith('Identified provider: stripe');

      // Verify signature verification logging
      expect(loggerSpy.debug).toHaveBeenCalledWith('Signature verified for stripe');
    });

    it('should log unknown webhook source warning', async () => {
      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(false);

      const req = createMockRequest({}, '{}');
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      expect(loggerSpy.warn).toHaveBeenCalledWith(
        'Unknown webhook source',
        expect.objectContaining({ headers: expect.any(Object) })
      );
    });

    it('should log invalid signature warning', async () => {
      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(false);

      const req = createMockRequest(
        { 'stripe-signature': 'invalid_sig' },
        '{}'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      expect(loggerSpy.warn).toHaveBeenCalledWith('Invalid signature for stripe webhook');
    });

    it('should log handler execution', async () => {
      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('test.event');

      const handler = jest.fn().mockResolvedValue('Success');
      router.on('stripe', 'test.event', handler);

      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      expect(loggerSpy.info).toHaveBeenCalledWith(
        'Executing handler for stripe/test.event',
        { eventId: 'evt_123' }
      );
    });

    it('should log handler errors', async () => {
      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('test.event');

      const error = new Error('Handler failed');
      const handler = jest.fn().mockRejectedValue(error);
      router.on('stripe', 'test.event', handler);

      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      expect(loggerSpy.error).toHaveBeenCalledWith(
        'Handler error for stripe/test.event',
        error,
        expect.objectContaining({
          provider: 'stripe',
          eventType: 'test.event',
          eventId: 'evt_123'
        })
      );
    });

    it('should handle parsing errors gracefully', async () => {
      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockImplementation(() => {
        throw new Error('Invalid JSON');
      });

      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        'invalid json'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      // Current implementation returns 400 but doesn't log parsing errors
      expect(res._statusCode).toBe(400);
      expect(res._data).toBe('Invalid payload');
    });
  });

  describe('NoOpLogger Integration', () => {
    it('should not produce any logs with NoOpLogger', async () => {
      const logger = new NoOpLogger();
      const spiedMethods = {
        debug: jest.spyOn(logger, 'debug'),
        info: jest.spyOn(logger, 'info'),
        warn: jest.spyOn(logger, 'warn'),
        error: jest.spyOn(logger, 'error')
      };

      const config: WebhookRouterConfig = {
        stripe: { signingSecret: 'stripe_secret' }
      };
      
      const router = new WebhookRouter(config, logger);

      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(false);

      const req = createMockRequest({}, '{}');
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      // All logger methods should have been called
      expect(spiedMethods.debug).toHaveBeenCalled();
      expect(spiedMethods.warn).toHaveBeenCalled();
      
      // But no actual output should occur (NoOp behavior verified in logger tests)
    });
  });

  describe('Log Level Filtering in Router Context', () => {
    it('should respect log level settings during request processing', async () => {
      const logger = new ConsoleLogger(LogLevel.NONE);
      
      // Mock console methods to verify filtering happens at console level
      const consoleSpies = {
        debug: jest.spyOn(console, 'debug').mockImplementation(),
        info: jest.spyOn(console, 'info').mockImplementation(),
        warn: jest.spyOn(console, 'warn').mockImplementation(),
        error: jest.spyOn(console, 'error').mockImplementation()
      };

      const config: WebhookRouterConfig = {
        stripe: { signingSecret: 'stripe_secret' }
      };
      
      const router = new WebhookRouter(config, logger);

      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(false);

      const req = createMockRequest(
        { 'stripe-signature': 'invalid' },
        '{}'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      // No logs should be called due to NONE log level
      expect(consoleSpies.debug).not.toHaveBeenCalled();
      expect(consoleSpies.info).not.toHaveBeenCalled();
      expect(consoleSpies.warn).not.toHaveBeenCalled();
      expect(consoleSpies.error).not.toHaveBeenCalled();
      
      // Cleanup
      Object.values(consoleSpies).forEach(spy => spy.mockRestore());
    });
  });

  describe('Performance Logging', () => {
    it('should complete requests without performance logging (not yet implemented)', async () => {
      const logger = new ConsoleLogger(LogLevel.DEBUG);
      loggerSpy = {
        debug: jest.spyOn(logger, 'debug').mockImplementation(),
        info: jest.spyOn(logger, 'info').mockImplementation(),
        warn: jest.spyOn(logger, 'warn').mockImplementation(),
        error: jest.spyOn(logger, 'error').mockImplementation()
      };

      const config: WebhookRouterConfig = {
        stripe: { signingSecret: 'stripe_secret' }
      };
      
      const router = new WebhookRouter(config, logger);

      const { StripeProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('test.event');

      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();

      await router.handle(req, res);
      await new Promise(resolve => setImmediate(resolve));

      // Should complete without errors (performance logging not yet implemented)
      expect(res._statusCode).toBe(200);
    });
  });
});