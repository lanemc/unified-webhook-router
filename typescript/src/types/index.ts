export interface WebhookEvent<T = any> {
  provider: string;
  type: string;
  id?: string;
  payload: T;
  rawHeaders: Record<string, string>;
  rawBody: string;
  receivedAt?: Date;
}

export interface WebhookProvider {
  name: string;
  identify: (headers: Record<string, string>, body: Buffer) => boolean;
  verify: (headers: Record<string, string>, rawBody: Buffer, config: any) => boolean;
  extractEventType: (headers: Record<string, string>, payload: any) => string;
  parsePayload: (rawBody: Buffer, headers: Record<string, string>) => any;
}

export interface WebhookRouterConfig {
  stripe?: {
    signingSecret: string;
    tolerance?: number;
  };
  github?: {
    secret: string;
    algorithm?: 'sha1' | 'sha256';
  };
  slack?: {
    signingSecret: string;
    tolerance?: number;
  };
  twilio?: {
    authToken: string;
  };
  square?: {
    signatureKey: string;
    notificationUrl: string;
  };
  [key: string]: any;
}

export type WebhookHandler<T = any> = (event: WebhookEvent<T>) => void | Promise<void> | any | Promise<any>;

export interface HandlerRegistry {
  [provider: string]: {
    [eventType: string]: WebhookHandler;
  };
}