import { IncomingMessage, ServerResponse } from 'http';
import {
  WebhookEvent,
  WebhookProvider,
  WebhookRouterConfig,
  WebhookHandler,
  HandlerRegistry
} from '../types';
import {
  StripeProvider,
  GitHubProvider,
  SlackProvider,
  TwilioProvider,
  SquareProvider
} from '../providers';
import { Logger, getDefaultLogger } from '../utils/logger';

export class WebhookRouter {
  private config: WebhookRouterConfig;
  private providers: Map<string, WebhookProvider> = new Map();
  private handlers: HandlerRegistry = {};
  private customProviders: Map<string, WebhookProvider> = new Map();
  private logger: Logger;
  
  constructor(config: WebhookRouterConfig, logger?: Logger) {
    this.config = config;
    this.logger = logger || getDefaultLogger();
    this.initializeProviders();
  }
  
  private initializeProviders(): void {
    // Register built-in providers
    if (this.config.stripe) {
      this.providers.set('stripe', StripeProvider);
    }
    if (this.config.github) {
      this.providers.set('github', GitHubProvider);
    }
    if (this.config.slack) {
      this.providers.set('slack', SlackProvider);
    }
    if (this.config.twilio) {
      this.providers.set('twilio', TwilioProvider);
    }
    if (this.config.square) {
      this.providers.set('square', SquareProvider);
    }
  }
  
  public on(provider: string, eventType: string, handler: WebhookHandler): void {
    if (!this.handlers[provider]) {
      this.handlers[provider] = {};
    }
    this.handlers[provider][eventType] = handler;
  }
  
  public registerProvider(provider: WebhookProvider): void {
    this.customProviders.set(provider.name, provider);
  }
  
  public async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      // Extract headers and body
      const headers = this.normalizeHeaders(req.headers);
      const rawBody = await this.getRawBody(req);
      
      this.logger.debug('Processing webhook request', { 
        headers: Object.keys(headers).join(', '),
        bodySize: rawBody.length 
      });
      
      // Identify provider
      const provider = this.identifyProvider(headers, rawBody);
      if (!provider) {
        this.logger.warn('Unknown webhook source', { headers });
        res.statusCode = 400;
        res.end('Unknown webhook source');
        return;
      }
      
      this.logger.debug(`Identified provider: ${provider.name}`);
      
      // Get provider config
      const providerConfig = this.config[provider.name];
      if (!providerConfig) {
        res.statusCode = 400;
        res.end('Provider not configured');
        return;
      }
      
      // Verify signature
      const isValid = provider.verify(headers, rawBody, providerConfig);
      if (!isValid) {
        this.logger.warn(`Invalid signature for ${provider.name} webhook`);
        res.statusCode = 403;
        res.end('Invalid signature');
        return;
      }
      
      this.logger.debug(`Signature verified for ${provider.name}`);
      
      // Parse payload
      let payload: any;
      try {
        payload = provider.parsePayload(rawBody, headers);
      } catch (error) {
        res.statusCode = 400;
        res.end('Invalid payload');
        return;
      }
      
      // Handle special cases
      if (provider.name === 'slack' && payload.type === 'url_verification') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain');
        res.end(payload.challenge);
        return;
      }
      
      // Extract event type
      const eventType = provider.extractEventType(headers, payload);
      
      // Create event object
      const event: WebhookEvent = {
        provider: provider.name,
        type: eventType,
        id: this.extractEventId(provider.name, headers, payload),
        payload,
        rawHeaders: headers,
        rawBody: rawBody.toString('utf8'),
        receivedAt: new Date()
      };
      
      // Find and execute handler
      const handler = this.findHandler(provider.name, eventType);
      
      if (handler) {
        try {
          this.logger.info(`Executing handler for ${provider.name}/${eventType}`, {
            eventId: event.id
          });
          
          const result = await handler(event);
          
          // Handle response
          if (result !== undefined && result !== null) {
            res.statusCode = 200;
            if (typeof result === 'object') {
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify(result));
            } else {
              res.end(String(result));
            }
          } else {
            res.statusCode = 200;
            res.end();
          }
          
          this.logger.info(`Successfully processed ${provider.name}/${eventType}`, {
            eventId: event.id
          });
        } catch (error) {
          this.logger.error(`Handler error for ${provider.name}/${eventType}`, error as Error, {
            provider: provider.name,
            eventType,
            eventId: event.id
          });
          res.statusCode = 500;
          res.end('Internal server error');
        }
      } else {
        // No handler found, but webhook is valid
        res.statusCode = 200;
        res.end();
      }
    } catch (error) {
      this.logger.error('Webhook processing error', error as Error);
      res.statusCode = 500;
      res.end('Internal server error');
    }
  }
  
  private normalizeHeaders(headers: IncomingMessage['headers']): Record<string, string> {
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      normalized[key.toLowerCase()] = Array.isArray(value) ? value[0] : value || '';
    }
    return normalized;
  }
  
  private async getRawBody(req: IncomingMessage): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }
  
  private identifyProvider(headers: Record<string, string>, body: Buffer): WebhookProvider | null {
    // Check built-in providers first
    for (const provider of this.providers.values()) {
      if (provider.identify(headers, body)) {
        return provider;
      }
    }
    
    // Check custom providers
    for (const provider of this.customProviders.values()) {
      if (provider.identify(headers, body)) {
        return provider;
      }
    }
    
    return null;
  }
  
  private findHandler(provider: string, eventType: string): WebhookHandler | null {
    const providerHandlers = this.handlers[provider];
    if (!providerHandlers) {
      return null;
    }
    
    // Check for exact match
    if (providerHandlers[eventType]) {
      return providerHandlers[eventType];
    }
    
    // Check for wildcard
    if (providerHandlers['*']) {
      return providerHandlers['*'];
    }
    
    return null;
  }
  
  private extractEventId(provider: string, headers: Record<string, string>, payload: any): string | undefined {
    switch (provider) {
      case 'stripe':
        return payload.id;
      case 'github':
        return headers['x-github-delivery'];
      case 'slack':
        return payload.event_id || payload.event?.event_id;
      default:
        return undefined;
    }
  }
}