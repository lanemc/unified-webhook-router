import { WebhookProvider } from '../types';
import { computeHMAC, timingSafeCompare } from '../utils/crypto';

export const GitHubProvider: WebhookProvider = {
  name: 'github',
  
  identify: (headers: Record<string, string>) => {
    return 'x-hub-signature' in headers || 'x-hub-signature-256' in headers;
  },
  
  verify: (headers: Record<string, string>, rawBody: Buffer, config: any) => {
    if (!config.secret) {
      return false;
    }
    
    const algorithm = config.algorithm || 'sha256';
    const signatureHeader = algorithm === 'sha256' ? 'x-hub-signature-256' : 'x-hub-signature';
    const signature = headers[signatureHeader];
    
    if (!signature) {
      return false;
    }
    
    const expectedSignature = `${algorithm}=${computeHMAC(algorithm, config.secret, rawBody)}`;
    
    return timingSafeCompare(signature, expectedSignature);
  },
  
  extractEventType: (headers: Record<string, string>) => {
    return headers['x-github-event'] || '';
  },
  
  parsePayload: (rawBody: Buffer) => {
    return JSON.parse(rawBody.toString('utf8'));
  }
};