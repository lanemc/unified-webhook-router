import * as crypto from 'crypto';
import { computeHMAC, computeHMACBase64, timingSafeCompare, isWithinTolerance } from '../../src/utils/crypto';

// Mock crypto module for some tests
jest.mock('crypto', () => ({
  ...jest.requireActual('crypto'),
  timingSafeEqual: jest.fn()
}));

describe('crypto utilities', () => {
  describe('computeHMAC', () => {
    it('should compute HMAC-SHA256 correctly', () => {
      const secret = 'test_secret';
      const message = 'test_message';
      
      const result = computeHMAC('sha256', secret, message);
      
      // Verify it's a hex string of correct length (64 chars for SHA256)
      expect(result).toMatch(/^[a-f0-9]{64}$/);
      
      // Verify consistency
      const result2 = computeHMAC('sha256', secret, message);
      expect(result).toBe(result2);
    });
    
    it('should compute HMAC-SHA1 correctly', () => {
      const secret = 'test_secret';
      const message = 'test_message';
      
      const result = computeHMAC('sha1', secret, message);
      
      // SHA1 produces 40 character hex string
      expect(result).toMatch(/^[a-f0-9]{40}$/);
    });
    
    it('should handle Buffer input', () => {
      const secret = 'test_secret';
      const message = Buffer.from('test_message', 'utf8');
      
      const result = computeHMAC('sha256', secret, message);
      const stringResult = computeHMAC('sha256', secret, 'test_message');
      
      expect(result).toBe(stringResult);
    });
    
    it('should produce different results for different messages', () => {
      const secret = 'test_secret';
      
      const result1 = computeHMAC('sha256', secret, 'message1');
      const result2 = computeHMAC('sha256', secret, 'message2');
      
      expect(result1).not.toBe(result2);
    });
    
    it('should produce different results for different secrets', () => {
      const message = 'test_message';
      
      const result1 = computeHMAC('sha256', 'secret1', message);
      const result2 = computeHMAC('sha256', 'secret2', message);
      
      expect(result1).not.toBe(result2);
    });
  });
  
  describe('computeHMACBase64', () => {
    it('should compute HMAC-SHA256 in base64', () => {
      const secret = 'test_secret';
      const message = 'test_message';
      
      const result = computeHMACBase64('sha256', secret, message);
      
      // Verify it's a valid base64 string
      expect(() => Buffer.from(result, 'base64')).not.toThrow();
      
      // Verify consistency
      const result2 = computeHMACBase64('sha256', secret, message);
      expect(result).toBe(result2);
    });
    
    it('should handle Buffer input', () => {
      const secret = 'test_secret';
      const message = Buffer.from('test_message', 'utf8');
      
      const result = computeHMACBase64('sha256', secret, message);
      const stringResult = computeHMACBase64('sha256', secret, 'test_message');
      
      expect(result).toBe(stringResult);
    });
    
    it('should produce different encoding than hex', () => {
      const secret = 'test_secret';
      const message = 'test_message';
      
      const hexResult = computeHMAC('sha256', secret, message);
      const base64Result = computeHMACBase64('sha256', secret, message);
      
      expect(hexResult).not.toBe(base64Result);
      
      // But they should represent the same bytes
      const hexBuffer = Buffer.from(hexResult, 'hex');
      const base64Buffer = Buffer.from(base64Result, 'base64');
      expect(hexBuffer.equals(base64Buffer)).toBe(true);
    });
  });
  
  describe('timingSafeCompare', () => {
    const mockTimingSafeEqual = crypto.timingSafeEqual as jest.MockedFunction<typeof crypto.timingSafeEqual>;
    
    beforeEach(() => {
      jest.clearAllMocks();
    });
    
    it('should return true for equal strings', () => {
      mockTimingSafeEqual.mockReturnValue(true);
      
      const result = timingSafeCompare('test123', 'test123');
      
      expect(result).toBe(true);
      expect(mockTimingSafeEqual).toHaveBeenCalledWith(
        Buffer.from('test123'),
        Buffer.from('test123')
      );
    });
    
    it('should return false for different strings', () => {
      mockTimingSafeEqual.mockReturnValue(false);
      
      const result = timingSafeCompare('test123', 'test456');
      
      expect(result).toBe(false);
    });
    
    it('should return false for different length strings without calling timingSafeEqual', () => {
      const result = timingSafeCompare('short', 'longer_string');
      
      expect(result).toBe(false);
      expect(mockTimingSafeEqual).not.toHaveBeenCalled();
    });
    
    it('should handle empty strings', () => {
      mockTimingSafeEqual.mockReturnValue(true);
      
      const result = timingSafeCompare('', '');
      
      expect(result).toBe(true);
      expect(mockTimingSafeEqual).toHaveBeenCalled();
    });
    
    it('should handle unicode strings', () => {
      mockTimingSafeEqual.mockReturnValue(true);
      
      const unicodeStr = '🚀 test';
      const result = timingSafeCompare(unicodeStr, unicodeStr);
      
      expect(result).toBe(true);
      expect(mockTimingSafeEqual).toHaveBeenCalledWith(
        Buffer.from(unicodeStr),
        Buffer.from(unicodeStr)
      );
    });
  });
  
  describe('isWithinTolerance', () => {
    it('should return true for current timestamp', () => {
      const now = Math.floor(Date.now() / 1000);
      
      const result = isWithinTolerance(now, 300);
      
      expect(result).toBe(true);
    });
    
    it('should return true for timestamp within tolerance (past)', () => {
      const now = Math.floor(Date.now() / 1000);
      const past = now - 100; // 100 seconds ago
      
      const result = isWithinTolerance(past, 300); // 5 minute tolerance
      
      expect(result).toBe(true);
    });
    
    it('should return true for timestamp within tolerance (future)', () => {
      const now = Math.floor(Date.now() / 1000);
      const future = now + 100; // 100 seconds in future
      
      const result = isWithinTolerance(future, 300); // 5 minute tolerance
      
      expect(result).toBe(true);
    });
    
    it('should return false for timestamp outside tolerance (past)', () => {
      const now = Math.floor(Date.now() / 1000);
      const past = now - 400; // 400 seconds ago
      
      const result = isWithinTolerance(past, 300); // 5 minute tolerance
      
      expect(result).toBe(false);
    });
    
    it('should return false for timestamp outside tolerance (future)', () => {
      const now = Math.floor(Date.now() / 1000);
      const future = now + 400; // 400 seconds in future
      
      const result = isWithinTolerance(future, 300); // 5 minute tolerance
      
      expect(result).toBe(false);
    });
    
    it('should handle exact boundary', () => {
      const now = Math.floor(Date.now() / 1000);
      const boundary = now - 300; // Exactly 300 seconds ago
      
      const result = isWithinTolerance(boundary, 300);
      
      expect(result).toBe(true);
    });
    
    it('should handle zero tolerance', () => {
      const now = Math.floor(Date.now() / 1000);
      
      const result1 = isWithinTolerance(now, 0);
      const result2 = isWithinTolerance(now - 1, 0);
      
      expect(result1).toBe(true);
      expect(result2).toBe(false);
    });
  });
});