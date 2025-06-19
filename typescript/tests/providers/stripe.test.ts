import { StripeProvider } from '../../src/providers/stripe';
import * as crypto from '../../src/utils/crypto';

// Mock crypto utilities
jest.mock('../../src/utils/crypto');

describe('StripeProvider', () => {
  const mockComputeHMAC = crypto.computeHMAC as jest.MockedFunction<typeof crypto.computeHMAC>;
  const mockTimingSafeCompare = crypto.timingSafeCompare as jest.MockedFunction<typeof crypto.timingSafeCompare>;
  const mockIsWithinTolerance = crypto.isWithinTolerance as jest.MockedFunction<typeof crypto.isWithinTolerance>;
  
  beforeEach(() => {
    jest.clearAllMocks();
  });
  
  describe('identify', () => {
    it('should identify Stripe webhooks by signature header', () => {
      const body = Buffer.from('{}');
      expect(StripeProvider.identify({ 'stripe-signature': 'sig_123' }, body)).toBe(true);
      expect(StripeProvider.identify({ 'x-hub-signature': 'sig_123' }, body)).toBe(false);
      expect(StripeProvider.identify({}, body)).toBe(false);
    });
  });
  
  describe('verify', () => {
    const config = { signingSecret: 'whsec_test_secret' };
    const timestamp = Math.floor(Date.now() / 1000);
    
    it('should verify valid signature', () => {
      const headers = { 
        'stripe-signature': `t=${timestamp},v1=valid_signature` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      mockIsWithinTolerance.mockReturnValue(true);
      mockComputeHMAC.mockReturnValue('valid_signature');
      mockTimingSafeCompare.mockReturnValue(true);
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(true);
      expect(mockIsWithinTolerance).toHaveBeenCalledWith(timestamp, 300);
      expect(mockComputeHMAC).toHaveBeenCalledWith(
        'sha256',
        'whsec_test_secret',
        `${timestamp}.{"test": "payload"}`
      );
      expect(mockTimingSafeCompare).toHaveBeenCalledWith('valid_signature', 'valid_signature');
    });
    
    it('should reject invalid signature', () => {
      const headers = { 
        'stripe-signature': `t=${timestamp},v1=invalid_signature` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      mockIsWithinTolerance.mockReturnValue(true);
      mockComputeHMAC.mockReturnValue('valid_signature');
      mockTimingSafeCompare.mockReturnValue(false);
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(false);
    });
    
    it('should reject expired timestamp', () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 400; // 400 seconds ago
      const headers = { 
        'stripe-signature': `t=${oldTimestamp},v1=valid_signature` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      mockIsWithinTolerance.mockReturnValue(false);
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(false);
      expect(mockIsWithinTolerance).toHaveBeenCalledWith(oldTimestamp, 300);
    });
    
    it('should handle custom tolerance', () => {
      const headers = { 
        'stripe-signature': `t=${timestamp},v1=valid_signature` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      const customConfig = { ...config, tolerance: 600 }; // 10 minutes
      
      mockIsWithinTolerance.mockReturnValue(true);
      mockComputeHMAC.mockReturnValue('valid_signature');
      mockTimingSafeCompare.mockReturnValue(true);
      
      StripeProvider.verify(headers, rawBody, customConfig);
      
      expect(mockIsWithinTolerance).toHaveBeenCalledWith(timestamp, 600);
    });
    
    it('should handle multiple signatures', () => {
      const headers = { 
        'stripe-signature': `t=${timestamp},v1=sig1,v1=sig2,v1=valid_signature` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      mockIsWithinTolerance.mockReturnValue(true);
      mockComputeHMAC.mockReturnValue('valid_signature');
      mockTimingSafeCompare
        .mockReturnValueOnce(false) // sig1
        .mockReturnValueOnce(false) // sig2
        .mockReturnValueOnce(true); // valid_signature
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(true);
      expect(mockTimingSafeCompare).toHaveBeenCalledTimes(3);
    });
    
    it('should return false if no signature header', () => {
      const headers = {};
      const rawBody = Buffer.from('{"test": "payload"}');
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(false);
    });
    
    it('should return false if no signing secret', () => {
      const headers = { 
        'stripe-signature': `t=${timestamp},v1=valid_signature` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      const result = StripeProvider.verify(headers, rawBody, {});
      
      expect(result).toBe(false);
    });
    
    it('should return false for malformed signature', () => {
      const headers = { 
        'stripe-signature': 'malformed_signature' 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(false);
    });
    
    it('should return false if no timestamp in signature', () => {
      const headers = { 
        'stripe-signature': 'v1=signature_without_timestamp' 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(false);
    });
    
    it('should return false if no v1 signatures', () => {
      const headers = { 
        'stripe-signature': `t=${timestamp},v0=other_version` 
      };
      const rawBody = Buffer.from('{"test": "payload"}');
      
      const result = StripeProvider.verify(headers, rawBody, config);
      
      expect(result).toBe(false);
    });
  });
  
  describe('extractEventType', () => {
    it('should extract event type from payload', () => {
      const payload = { type: 'payment_intent.succeeded', id: 'evt_123' };
      
      expect(StripeProvider.extractEventType({}, payload)).toBe('payment_intent.succeeded');
    });
    
    it('should return empty string if no type', () => {
      const payload = { id: 'evt_123' };
      
      expect(StripeProvider.extractEventType({}, payload)).toBe('');
    });
    
    it('should handle undefined payload type', () => {
      const payload = { type: undefined };
      
      expect(StripeProvider.extractEventType({}, payload)).toBe('');
    });
  });
  
  describe('parsePayload', () => {
    it('should parse JSON payload', () => {
      const rawBody = Buffer.from('{"id": "evt_123", "type": "test"}');
      const headers = {};
      
      const result = StripeProvider.parsePayload(rawBody, headers);
      
      expect(result).toEqual({ id: 'evt_123', type: 'test' });
    });
    
    it('should throw on invalid JSON', () => {
      const rawBody = Buffer.from('invalid json');
      const headers = {};
      
      expect(() => StripeProvider.parsePayload(rawBody, headers)).toThrow();
    });
    
    it('should handle empty payload', () => {
      const rawBody = Buffer.from('{}');
      const headers = {};
      
      const result = StripeProvider.parsePayload(rawBody, headers);
      
      expect(result).toEqual({});
    });
    
    it('should handle complex nested JSON', () => {
      const complexPayload = {
        id: 'evt_123',
        type: 'payment_intent.succeeded',
        data: {
          object: {
            amount: 1000,
            currency: 'usd',
            metadata: {
              order_id: '12345'
            }
          }
        }
      };
      const rawBody = Buffer.from(JSON.stringify(complexPayload));
      const headers = {};
      
      const result = StripeProvider.parsePayload(rawBody, headers);
      
      expect(result).toEqual(complexPayload);
    });
  });
});