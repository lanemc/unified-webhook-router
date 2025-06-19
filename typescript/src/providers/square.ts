import { WebhookProvider } from '../types';
import { computeHMACBase64, timingSafeCompare } from '../utils/crypto';

export const SquareProvider: WebhookProvider = {
  name: 'square',
  
  identify: (headers: Record<string, string>) => {
    return 'x-square-hmacsha256-signature' in headers;
  },
  
  verify: (headers: Record<string, string>, rawBody: Buffer, config: any) => {
    const signature = headers['x-square-hmacsha256-signature'];
    if (!signature || !config.signatureKey || !config.notificationUrl) {
      return false;
    }
    
    // Square uses notification URL + raw body as the message
    const message = config.notificationUrl + rawBody.toString('utf8');
    const expectedSignature = computeHMACBase64('sha256', config.signatureKey, message);
    
    return timingSafeCompare(signature, expectedSignature);
  },
  
  extractEventType: (headers: Record<string, string>, payload: any) => {
    return payload.type || '';
  },
  
  parsePayload: (rawBody: Buffer) => {
    return JSON.parse(rawBody.toString('utf8'));
  }
};