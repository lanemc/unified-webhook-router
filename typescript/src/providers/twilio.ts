import { WebhookProvider } from '../types';
import { computeHMAC, timingSafeCompare } from '../utils/crypto';
import * as crypto from 'crypto';

export const TwilioProvider: WebhookProvider = {
  name: 'twilio',
  
  identify: (headers: Record<string, string>) => {
    return 'x-twilio-signature' in headers;
  },
  
  verify: (headers: Record<string, string>, rawBody: Buffer, config: any) => {
    const signature = headers['x-twilio-signature'];
    if (!signature || !config.authToken) {
      return false;
    }
    
    // For Twilio, we need the full URL which should be passed in config
    const url = headers['x-forwarded-proto'] + '://' + headers['host'] + headers['x-original-url'] || config.webhookUrl || '';
    
    // Parse the body to get parameters
    const contentType = headers['content-type'] || '';
    let params: Record<string, string> = {};
    
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const searchParams = new URLSearchParams(rawBody.toString('utf8'));
      searchParams.forEach((value, key) => {
        params[key] = value;
      });
    } else if (contentType.includes('application/json')) {
      params = JSON.parse(rawBody.toString('utf8'));
    }
    
    // Sort parameters alphabetically and concatenate
    const sortedKeys = Object.keys(params).sort();
    let data = url;
    
    for (const key of sortedKeys) {
      data += key + params[key];
    }
    
    // Compute HMAC-SHA1
    const expectedSignature = crypto
      .createHmac('sha1', config.authToken)
      .update(data)
      .digest('base64');
    
    return timingSafeCompare(signature, expectedSignature);
  },
  
  extractEventType: (headers: Record<string, string>, payload: any) => {
    // Twilio doesn't have a specific event type field
    // We can use the webhook type based on the payload
    if (payload.MessageStatus) {
      return 'message.status';
    } else if (payload.CallStatus) {
      return 'call.status';
    } else if (payload.Body && payload.From) {
      return 'message.received';
    }
    return 'webhook';
  },
  
  parsePayload: (rawBody: Buffer, headers: Record<string, string>) => {
    const contentType = headers['content-type'] || '';
    
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(rawBody.toString('utf8'));
      const payload: any = {};
      for (const [key, value] of params) {
        payload[key] = value;
      }
      return payload;
    } else {
      return JSON.parse(rawBody.toString('utf8'));
    }
  }
};