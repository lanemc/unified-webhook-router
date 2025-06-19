import { WebhookProvider } from '../types';
import { computeHMAC, timingSafeCompare, isWithinTolerance } from '../utils/crypto';

export const StripeProvider: WebhookProvider = {
  name: 'stripe',
  
  identify: (headers: Record<string, string>) => {
    return 'stripe-signature' in headers;
  },
  
  verify: (headers: Record<string, string>, rawBody: Buffer, config: any) => {
    const signature = headers['stripe-signature'];
    if (!signature || !config.signingSecret) {
      return false;
    }
    
    const tolerance = config.tolerance || 300; // 5 minutes default
    const elements = signature.split(',');
    const signatures: string[] = [];
    let timestamp = 0;
    
    for (const element of elements) {
      const [key, value] = element.split('=');
      if (key === 't') {
        timestamp = parseInt(value, 10);
      } else if (key === 'v1') {
        signatures.push(value);
      }
    }
    
    if (!timestamp || signatures.length === 0) {
      return false;
    }
    
    if (!isWithinTolerance(timestamp, tolerance)) {
      return false;
    }
    
    const signedPayload = `${timestamp}.${rawBody.toString('utf8')}`;
    const expectedSignature = computeHMAC('sha256', config.signingSecret, signedPayload);
    
    return signatures.some(sig => timingSafeCompare(sig, expectedSignature));
  },
  
  extractEventType: (headers: Record<string, string>, payload: any) => {
    return payload.type || '';
  },
  
  parsePayload: (rawBody: Buffer, headers: Record<string, string>) => {
    return JSON.parse(rawBody.toString('utf8'));
  }
};