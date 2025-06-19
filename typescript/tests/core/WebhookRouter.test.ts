import { WebhookRouter } from '../../src/core/WebhookRouter';
import { WebhookEvent, WebhookProvider, WebhookRouterConfig } from '../../src/types';
import { NoOpLogger } from '../../src/utils/logger';
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
  },
  SlackProvider: {
    name: 'slack',
    identify: jest.fn(),
    verify: jest.fn(),
    parsePayload: jest.fn(),
    extractEventType: jest.fn()
  },
  TwilioProvider: {
    name: 'twilio',
    identify: jest.fn(),
    verify: jest.fn(),
    parsePayload: jest.fn(),
    extractEventType: jest.fn()
  },
  SquareProvider: {
    name: 'square',
    identify: jest.fn(),
    verify: jest.fn(),
    parsePayload: jest.fn(),
    extractEventType: jest.fn()
  }
}));

// Helper to create mock request
function createMockRequest(headers: Record<string, string>, body: string): IncomingMessage {
  const req = new EventEmitter() as IncomingMessage;
  req.headers = headers;
  
  // Simulate body stream
  setImmediate(() => {
    req.emit('data', Buffer.from(body));
    req.emit('end');
  });
  
  return req;
}

// Helper to create mock response
function createMockResponse(): ServerResponse & { _statusCode?: number; _data?: string; _headers?: Record<string, string> } {
  const res = new EventEmitter() as ServerResponse & { 
    _statusCode?: number; 
    _data?: string; 
    _headers?: Record<string, string> 
  };
  
  res._headers = {};
  res.statusCode = 200;
  
  res.setHeader = jest.fn((name: string, value: string) => {
    res._headers![name] = value;
    return res;
  });
  
  res.end = jest.fn((data?: any) => {
    res._data = data;
    res._statusCode = res.statusCode;
  }) as any;
  
  return res;
}

describe('WebhookRouter', () => {
  let router: WebhookRouter;
  let config: WebhookRouterConfig;
  
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    config = {
      stripe: {
        signingSecret: 'stripe_secret'
      },
      github: {
        secret: 'github_secret'
      }
    };
    
    router = new WebhookRouter(config, new NoOpLogger());
  });
  
  describe('constructor', () => {
    it('should initialize with provided config', () => {
      expect(router).toBeInstanceOf(WebhookRouter);
    });
    
    it('should initialize providers based on config', () => {
      const fullConfig: WebhookRouterConfig = {
        stripe: { signingSecret: 'stripe_secret' },
        github: { secret: 'github_secret' },
        slack: { signingSecret: 'slack_secret' },
        twilio: { authToken: 'twilio_token' },
        square: { signatureKey: 'square_key', notificationUrl: 'https://example.com/webhook' }
      };
      
      const fullRouter = new WebhookRouter(fullConfig, new NoOpLogger());
      expect(fullRouter).toBeInstanceOf(WebhookRouter);
    });
  });
  
  describe('on', () => {
    it('should register event handlers', () => {
      const handler = jest.fn();
      
      router.on('stripe', 'payment_intent.succeeded', handler);
      router.on('stripe', 'customer.created', handler);
      router.on('github', 'push', handler);
      
      // Handler should be registered (we'll test execution in handle tests)
      expect(handler).not.toHaveBeenCalled();
    });
    
    it('should register wildcard handlers', () => {
      const handler = jest.fn();
      
      router.on('stripe', '*', handler);
      
      expect(handler).not.toHaveBeenCalled();
    });
  });
  
  describe('registerProvider', () => {
    it('should register custom providers', () => {
      const customProvider: WebhookProvider = {
        name: 'custom',
        identify: jest.fn(),
        verify: jest.fn(),
        parsePayload: jest.fn(),
        extractEventType: jest.fn()
      };
      
      router.registerProvider(customProvider);
      
      // Provider should be registered (we'll test usage in handle tests)
      expect(customProvider.identify).not.toHaveBeenCalled();
    });
  });
  
  describe('handle', () => {
    it('should handle valid Stripe webhook', async () => {
      const { StripeProvider } = require('../../src/providers');
      const handler = jest.fn().mockResolvedValue({ success: true });
      
      // Setup mocks
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123', type: 'payment_intent.succeeded' });
      StripeProvider.extractEventType.mockReturnValue('payment_intent.succeeded');
      
      router.on('stripe', 'payment_intent.succeeded', handler);
      
      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123", "type": "payment_intent.succeeded"}'
      );
      const res = createMockResponse();
      
      await router.handle(req, res);
      
      // Allow async operations to complete
      await new Promise(resolve => setImmediate(resolve));
      
      expect(StripeProvider.identify).toHaveBeenCalled();
      expect(StripeProvider.verify).toHaveBeenCalled();
      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'stripe',
          type: 'payment_intent.succeeded',
          id: 'evt_123',
          payload: { id: 'evt_123', type: 'payment_intent.succeeded' }
        })
      );
      expect(res._statusCode).toBe(200);
      expect(res._data).toBe('{"success":true}');
    });
    
    it('should return 400 for unknown webhook source', async () => {
      const { StripeProvider, GitHubProvider } = require('../../src/providers');
      
      StripeProvider.identify.mockReturnValue(false);
      GitHubProvider.identify.mockReturnValue(false);
      
      const req = createMockRequest({}, '{}');
      const res = createMockResponse();
      
      await router.handle(req, res);
      
      await new Promise(resolve => setImmediate(resolve));
      
      expect(res._statusCode).toBe(400);
      expect(res._data).toBe('Unknown webhook source');
    });
    
    it('should return 403 for invalid signature', async () => {
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
      
      expect(res._statusCode).toBe(403);
      expect(res._data).toBe('Invalid signature');
    });
    
    it('should handle wildcard handlers', async () => {
      const { StripeProvider } = require('../../src/providers');
      const wildcardHandler = jest.fn().mockResolvedValue(undefined);
      
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('unknown.event');
      
      router.on('stripe', '*', wildcardHandler);
      
      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();
      
      await router.handle(req, res);
      
      await new Promise(resolve => setImmediate(resolve));
      
      expect(wildcardHandler).toHaveBeenCalled();
      expect(res._statusCode).toBe(200);
    });
    
    it('should handle Slack URL verification challenge', async () => {
      const { SlackProvider } = require('../../src/providers');
      
      SlackProvider.identify.mockReturnValue(true);
      SlackProvider.verify.mockReturnValue(true);
      SlackProvider.parsePayload.mockReturnValue({ 
        type: 'url_verification',
        challenge: 'test_challenge_123'
      });
      
      const slackConfig = { slack: { signingSecret: 'slack_secret' } };
      const slackRouter = new WebhookRouter(slackConfig, new NoOpLogger());
      
      const req = createMockRequest(
        { 'x-slack-signature': 'sig_123' },
        '{"type": "url_verification", "challenge": "test_challenge_123"}'
      );
      const res = createMockResponse();
      
      await slackRouter.handle(req, res);
      
      await new Promise(resolve => setImmediate(resolve));
      
      expect(res._statusCode).toBe(200);
      expect(res._data).toBe('test_challenge_123');
      expect(res._headers!['Content-Type']).toBe('text/plain');
    });
    
    it('should handle handler errors gracefully', async () => {
      const { StripeProvider } = require('../../src/providers');
      const errorHandler = jest.fn().mockRejectedValue(new Error('Handler error'));
      
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('test.event');
      
      router.on('stripe', 'test.event', errorHandler);
      
      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();
      
      await router.handle(req, res);
      
      await new Promise(resolve => setImmediate(resolve));
      
      expect(errorHandler).toHaveBeenCalled();
      expect(res._statusCode).toBe(500);
      expect(res._data).toBe('Internal server error');
    });
    
    it('should return 200 when no handler is registered', async () => {
      const { StripeProvider } = require('../../src/providers');
      
      StripeProvider.identify.mockReturnValue(true);
      StripeProvider.verify.mockReturnValue(true);
      StripeProvider.parsePayload.mockReturnValue({ id: 'evt_123' });
      StripeProvider.extractEventType.mockReturnValue('unhandled.event');
      
      const req = createMockRequest(
        { 'stripe-signature': 'sig_123' },
        '{"id": "evt_123"}'
      );
      const res = createMockResponse();
      
      await router.handle(req, res);
      
      await new Promise(resolve => setImmediate(resolve));
      
      expect(res._statusCode).toBe(200);
      expect(res._data).toBeUndefined();
    });
    
    it('should handle custom providers', async () => {
      // Make sure built-in providers don't match
      const { StripeProvider, GitHubProvider } = require('../../src/providers');
      StripeProvider.identify.mockReturnValue(false);
      GitHubProvider.identify.mockReturnValue(false);
      
      const customProvider: WebhookProvider = {
        name: 'custom',
        identify: jest.fn().mockReturnValue(true),
        verify: jest.fn().mockReturnValue(true),
        parsePayload: jest.fn().mockReturnValue({ custom: 'data' }),
        extractEventType: jest.fn().mockReturnValue('custom.event')
      };
      
      const customHandler = jest.fn().mockResolvedValue('Custom response');
      
      // Need to add custom provider to the config
      const customConfig = {
        ...config,
        custom: {
          customSetting: 'value'
        }
      };
      const customRouter = new WebhookRouter(customConfig, new NoOpLogger());
      
      customRouter.registerProvider(customProvider);
      customRouter.on('custom', 'custom.event', customHandler);
      
      const req = createMockRequest(
        { 'x-custom-header': 'value' },
        '{"custom": "data"}'
      );
      const res = createMockResponse();
      
      await customRouter.handle(req, res);
      
      // Wait for all async operations to complete
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(customProvider.identify).toHaveBeenCalled();
      expect(customProvider.verify).toHaveBeenCalled();
      expect(customHandler).toHaveBeenCalled();
      expect(res._statusCode).toBe(200);
      expect(res._data).toBe('Custom response');
    });
    
    it('should handle invalid payload gracefully', async () => {
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
      
      expect(res._statusCode).toBe(400);
      expect(res._data).toBe('Invalid payload');
    });
  });
});