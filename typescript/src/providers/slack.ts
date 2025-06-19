import { WebhookProvider } from '../types';
import { computeHMAC, timingSafeCompare, isWithinTolerance } from '../utils/crypto';

export const SlackProvider: WebhookProvider = {
  name: 'slack',
  
  identify: (headers: Record<string, string>) => {
    return 'x-slack-signature' in headers && 'x-slack-request-timestamp' in headers;
  },
  
  verify: (headers: Record<string, string>, rawBody: Buffer, config: any) => {
    const signature = headers['x-slack-signature'];
    const timestamp = headers['x-slack-request-timestamp'];
    
    if (!signature || !timestamp || !config.signingSecret) {
      return false;
    }
    
    const timestampNum = parseInt(timestamp, 10);
    const tolerance = config.tolerance || 300; // 5 minutes default
    
    if (!isWithinTolerance(timestampNum, tolerance)) {
      return false;
    }
    
    const baseString = `v0:${timestamp}:${rawBody.toString('utf8')}`;
    const expectedSignature = `v0=${computeHMAC('sha256', config.signingSecret, baseString)}`;
    
    return timingSafeCompare(signature, expectedSignature);
  },
  
  extractEventType: (headers: Record<string, string>, payload: any) => {
    // Handle different Slack event types
    if (payload.type === 'url_verification') {
      return 'url_verification';
    } else if (payload.type === 'event_callback' && payload.event) {
      return payload.event.type;
    } else if (payload.command) {
      return payload.command; // Slash commands
    } else if (payload.type) {
      return payload.type;
    }
    return '';
  },
  
  parsePayload: (rawBody: Buffer, headers: Record<string, string>) => {
    const contentType = headers['content-type'] || '';
    
    if (contentType.includes('application/x-www-form-urlencoded')) {
      // Parse form data for slash commands
      const params = new URLSearchParams(rawBody.toString('utf8'));
      const payload: any = {};
      for (const [key, value] of params) {
        payload[key] = value;
      }
      return payload;
    } else {
      // Parse JSON for Events API
      return JSON.parse(rawBody.toString('utf8'));
    }
  }
};