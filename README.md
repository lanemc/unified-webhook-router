# 🎯 Unified Webhook Router

**The developer-friendly way to handle webhooks from any provider. Secure by default, framework agnostic, and delightfully simple.**

[![npm version](https://badge.fury.io/js/unified-webhook-router.svg)](https://badge.fury.io/js/unified-webhook-router)
[![PyPI version](https://badge.fury.io/py/unified-webhook-router.svg)](https://badge.fury.io/py/unified-webhook-router)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)

---

## 🚀 Why You'll Love This

**Before:** Wrestling with different webhook formats, security implementations, and provider-specific quirks.

```javascript
// The old way: different code for every provider 😫
app.post('/stripe-webhooks', (req, res) => {
  const sig = req.headers['stripe-signature'];
  // Manually implement Stripe's signature verification...
  const payload = stripe.webhooks.constructEvent(body, sig, secret);
  // Handle Stripe events...
});

app.post('/github-webhooks', (req, res) => {
  const sig = req.headers['x-hub-signature-256'];
  // Manually implement GitHub's different signature scheme...
  // Handle GitHub events...
});

// And so on for every provider... 🤯
```

**After:** One beautiful API that handles everything securely.

```javascript
// The new way: one router, all providers, zero security worries ✨
const router = new WebhookRouter({
  stripe: { signingSecret: process.env.STRIPE_SIGNING_SECRET },
  github: { secret: process.env.GITHUB_WEBHOOK_SECRET },
  slack: { signingSecret: process.env.SLACK_SIGNING_SECRET }
});

router.on('stripe', 'payment_intent.succeeded', async (event) => {
  console.log(`💳 Payment ${event.payload.id} succeeded!`);
});

router.on('github', 'push', async (event) => {
  console.log(`🚀 New push to ${event.payload.repository.full_name}`);
});

// One endpoint handles everything
app.post('/webhooks', express.raw({ type: '*/*' }), (req, res) => {
  router.handle(req, res);
});
```

---

## ✨ Features That Make Development a Joy

- 🔐 **Security Built-In**: HMAC verification, replay protection, timing-safe comparisons—all automated
- 🚀 **Framework Agnostic**: Works with Express, Next.js, Flask, Django, FastAPI, and more
- ☁️ **Serverless Ready**: Perfect for AWS Lambda, Vercel, Netlify Functions
- 🔌 **Provider Rich**: Stripe, GitHub, Slack, Twilio, Square + easy custom providers
- 📦 **Dual Language**: TypeScript/Node.js and Python with identical APIs
- ⚡ **Type Safe**: Full TypeScript definitions and Python type hints
- 🛡️ **Zero Trust**: Every webhook is verified before your code runs
- 🎯 **Developer First**: Designed for happiness, not just functionality

---

## 📦 Installation

### TypeScript/Node.js
```bash
npm install unified-webhook-router
# or
yarn add unified-webhook-router
```

### Python
```bash
pip install unified-webhook-router
```

---

## 🏁 Quick Start

### TypeScript/Node.js

```typescript
import express from 'express';
import { WebhookRouter } from 'unified-webhook-router';

const app = express();
const router = new WebhookRouter({
  stripe: { signingSecret: process.env.STRIPE_SIGNING_SECRET! },
  github: { secret: process.env.GITHUB_WEBHOOK_SECRET! }
});

// Handle successful payments
router.on('stripe', 'payment_intent.succeeded', async (event) => {
  const payment = event.payload;
  console.log(`💰 Received $${payment.amount / 100} from ${payment.customer}`);
  
  // Your business logic here
  await fulfillOrder(payment.metadata.order_id);
});

// Handle code pushes
router.on('github', 'push', async (event) => {
  const { repository, commits } = event.payload;
  console.log(`📝 ${commits.length} commits pushed to ${repository.full_name}`);
  
  // Trigger your CI/CD pipeline
  await triggerDeployment(repository.full_name, commits);
});

// Single endpoint for all webhooks
app.post('/webhooks', express.raw({ type: '*/*' }), (req, res) => {
  router.handle(req, res);
});

app.listen(3000, () => {
  console.log('🎯 Webhook server ready at http://localhost:3000');
});
```

### Python

```python
from flask import Flask, request
from unified_webhook_router import WebhookRouter, InvalidWebhookError

app = Flask(__name__)
router = WebhookRouter({
    'stripe': {'signing_secret': os.environ['STRIPE_SIGNING_SECRET']},
    'github': {'secret': os.environ['GITHUB_WEBHOOK_SECRET']}
})

@router.on('stripe', 'payment_intent.succeeded')
async def handle_payment(event):
    payment = event.payload
    print(f"💰 Received ${payment['amount'] / 100} from {payment['customer']}")
    
    # Your business logic here
    await fulfill_order(payment['metadata']['order_id'])

@router.on('github', 'push')
async def handle_push(event):
    repo = event.payload['repository']['full_name']
    commits = event.payload['commits']
    print(f"📝 {len(commits)} commits pushed to {repo}")
    
    # Trigger your CI/CD pipeline
    await trigger_deployment(repo, commits)

@app.route('/webhooks', methods=['POST'])
async def webhooks():
    try:
        result = await router.handle_request(request)
        return result or '', 200
    except InvalidWebhookError:
        return 'Invalid webhook', 400

if __name__ == '__main__':
    app.run(port=3000)
```

---

## 🎪 Framework Examples

### Next.js API Routes

```typescript
// pages/api/webhooks.ts
import { WebhookRouter } from 'unified-webhook-router';

const router = new WebhookRouter({
  stripe: { signingSecret: process.env.STRIPE_SIGNING_SECRET! }
});

router.on('stripe', 'checkout.session.completed', async (event) => {
  // Handle successful checkout
  await processOrder(event.payload);
});

export const config = {
  api: { bodyParser: false } // Important: disable body parsing
};

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    return router.handle(req, res);
  }
  res.status(405).end();
}
```

### AWS Lambda

```typescript
import { WebhookRouter } from 'unified-webhook-router';

const router = new WebhookRouter({
  stripe: { signingSecret: process.env.STRIPE_SIGNING_SECRET! }
});

router.on('stripe', '*', async (event) => {
  console.log(`Stripe event: ${event.type}`);
});

export const handler = async (event: APIGatewayProxyEvent) => {
  try {
    // Convert Lambda event to standard request format
    const mockReq = {
      headers: event.headers,
      body: Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8')
    };
    
    const result = await router.handleLambda(mockReq);
    return {
      statusCode: 200,
      body: result ? JSON.stringify(result) : ''
    };
  } catch (error) {
    return {
      statusCode: 400,
      body: 'Invalid webhook'
    };
  }
};
```

### Django

```python
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from unified_webhook_router import WebhookRouter, InvalidWebhookError

router = WebhookRouter({
    'stripe': {'signing_secret': os.environ['STRIPE_SIGNING_SECRET']}
})

@router.on('stripe', 'invoice.paid')
def handle_invoice_paid(event):
    invoice = event.payload
    print(f"📧 Invoice {invoice['id']} paid: ${invoice['amount_paid'] / 100}")

@csrf_exempt
def webhooks(request):
    if request.method == 'POST':
        try:
            result = router.handle_request(request)
            return HttpResponse(result or '', status=200)
        except InvalidWebhookError:
            return HttpResponse('Invalid webhook', status=400)
    return HttpResponse('Method not allowed', status=405)
```

### FastAPI

```python
from fastapi import FastAPI, Request, HTTPException
from unified_webhook_router import WebhookRouter, InvalidWebhookError

app = FastAPI()
router = WebhookRouter({
    'stripe': {'signing_secret': os.environ['STRIPE_SIGNING_SECRET']}
})

@router.on('stripe', 'customer.subscription.created')
async def handle_new_subscription(event):
    subscription = event.payload
    print(f"🎉 New subscription: {subscription['id']}")

@app.post("/webhooks")
async def webhooks(request: Request):
    try:
        result = await router.handle_request(request)
        return result or {}
    except InvalidWebhookError:
        raise HTTPException(status_code=400, detail="Invalid webhook")
```

---

## 🔐 Supported Providers

| Provider | Verification Method | Special Features |
|----------|-------------------|------------------|
| **Stripe** | HMAC SHA-256 + timestamp | ✅ Replay protection, tolerance config |
| **GitHub** | HMAC SHA-1/256 | ✅ Algorithm selection, delivery ID tracking |
| **Slack** | HMAC SHA-256 + timestamp | ✅ URL verification challenges, slash commands |
| **Twilio** | HMAC SHA-1 + URL validation | ✅ Form/JSON payload support |
| **Square** | HMAC SHA-256 + URL | ✅ Notification URL verification |

### Provider Configuration

```typescript
const router = new WebhookRouter({
  stripe: {
    signingSecret: 'whsec_...',
    tolerance: 300 // Optional: 5 minutes (default)
  },
  github: {
    secret: 'your-github-secret',
    algorithm: 'sha256' // Optional: 'sha256' or 'sha1'
  },
  slack: {
    signingSecret: 'your-slack-secret',
    tolerance: 300 // Optional: 5 minutes (default)
  },
  twilio: {
    authToken: 'your-twilio-auth-token'
  },
  square: {
    signatureKey: 'your-square-signature-key',
    notificationUrl: 'https://yourdomain.com/webhooks'
  }
});
```

---

## 🎯 Event Handling

### Basic Handlers

```typescript
// Handle specific events
router.on('stripe', 'payment_intent.succeeded', handlePayment);
router.on('github', 'push', handlePush);
router.on('slack', 'reaction_added', handleReaction);

// Wildcard handlers for all events from a provider
router.on('stripe', '*', (event) => {
  console.log(`Stripe event: ${event.type}`);
});

// Multiple handlers
router.on('github', 'push', logPush);
router.on('github', 'push', triggerCI);
router.on('github', 'push', notifyTeam);
```

### Event Object Structure

Every handler receives a normalized event object:

```typescript
interface WebhookEvent<T = any> {
  provider: string;     // 'stripe', 'github', etc.
  type: string;         // 'payment_intent.succeeded', 'push', etc.
  id?: string;          // Event ID when available
  payload: T;           // The parsed webhook payload
  rawHeaders: Record<string, string>;
  rawBody: string;      // Original request body
  receivedAt: Date;     // When we received it
}
```

### Async Handlers

```typescript
// TypeScript/Node.js
router.on('stripe', 'payment_intent.succeeded', async (event) => {
  await updateDatabase(event.payload);
  await sendConfirmationEmail(event.payload.customer);
  await triggerFulfillment(event.payload.metadata.order_id);
});

# Python
@router.on('stripe', 'payment_intent.succeeded')
async def handle_payment(event):
    await update_database(event.payload)
    await send_confirmation_email(event.payload['customer'])
    await trigger_fulfillment(event.payload['metadata']['order_id'])
```

### Response Handling

Some webhooks expect specific responses:

```typescript
// Slack slash commands
router.on('slack', '/deploy', (event) => {
  const { user_name, text } = event.payload;
  
  // Trigger deployment
  triggerDeploy(text);
  
  // Respond to Slack
  return {
    text: `🚀 Deployment of \`${text}\` started by ${user_name}!`,
    response_type: 'in_channel'
  };
});

// Slack URL verification (handled automatically)
// The router automatically responds to Slack's challenge requests
```

---

## 🔧 Advanced Usage

### Custom Providers

Add support for any webhook provider:

```typescript
import { WebhookProvider } from 'unified-webhook-router';

const customProvider: WebhookProvider = {
  name: 'myservice',
  
  identify: (headers) => {
    return 'x-myservice-signature' in headers;
  },
  
  verify: (headers, rawBody, config) => {
    const signature = headers['x-myservice-signature'];
    const expected = computeHMAC('sha256', config.secret, rawBody);
    return timingSafeCompare(signature, expected);
  },
  
  extractEventType: (headers, payload) => {
    return payload.event_type;
  },
  
  parsePayload: (rawBody) => {
    return JSON.parse(rawBody.toString('utf8'));
  }
};

router.registerProvider(customProvider);

// Now you can use it
router.on('myservice', 'user.created', handleNewUser);
```

### Environment Configuration

```typescript
// Use environment variables for secrets
const router = new WebhookRouter({
  stripe: { 
    signingSecret: process.env.STRIPE_SIGNING_SECRET 
  },
  github: { 
    secret: process.env.GITHUB_WEBHOOK_SECRET 
  },
  slack: { 
    signingSecret: process.env.SLACK_SIGNING_SECRET 
  }
});

// Or use a configuration object
const config = {
  stripe: { signingSecret: getSecret('stripe') },
  github: { secret: getSecret('github') }
};
```

### Error Handling

```typescript
// Custom error handling
router.on('stripe', 'payment_intent.succeeded', async (event) => {
  try {
    await processPayment(event.payload);
  } catch (error) {
    console.error('Payment processing failed:', error);
    await logFailure(event, error);
    throw error; // Re-throw to trigger webhook retry
  }
});

// Global error handler
router.onError((error, event) => {
  console.error(`Webhook error for ${event.provider}/${event.type}:`, error);
  notifyTeam(error, event);
});
```

### Testing Webhooks

```typescript
// Create test events for unit testing
const testEvent = router.createTestEvent('stripe', 'payment_intent.succeeded', {
  id: 'pi_test_123',
  amount: 2000,
  currency: 'usd',
  status: 'succeeded'
});

await myHandler(testEvent);
```

---

## 🛡️ Security Features

The router implements security best practices automatically:

### ✅ What's Protected

- **Signature Verification**: Every webhook is cryptographically verified
- **Replay Attack Prevention**: Timestamp validation prevents old requests
- **Timing Attack Prevention**: Constant-time comparison prevents timing analysis
- **Raw Body Integrity**: Signatures computed on exact received bytes
- **Secret Safety**: No secrets logged or exposed in errors

### 🔒 Security Details by Provider

**Stripe:**
- Verifies `Stripe-Signature` header using HMAC SHA-256
- Validates timestamp within tolerance window (default: 5 minutes)
- Supports multiple signature versions

**GitHub:**
- Verifies `X-Hub-Signature-256` (preferred) or `X-Hub-Signature`
- Uses HMAC SHA-256 or SHA-1 with your webhook secret
- Validates against raw request body

**Slack:**
- Verifies `X-Slack-Signature` using HMAC SHA-256
- Validates `X-Slack-Request-Timestamp` within tolerance
- Automatically handles URL verification challenges

**Twilio:**
- Verifies `X-Twilio-Signature` using HMAC SHA-1
- Validates against URL + sorted parameters
- Supports both JSON and form-encoded payloads

**Square:**
- Verifies `X-Square-Hmacsha256-Signature` using HMAC SHA-256
- Validates against notification URL + request body
- Base64 signature decoding

---

## 🚨 Error Handling

The router provides clear error handling:

```typescript
try {
  await router.handle(req, res);
} catch (error) {
  if (error instanceof InvalidWebhookError) {
    // Invalid signature, expired timestamp, etc.
    console.log('Webhook rejected:', error.message);
    res.status(400).send('Invalid webhook');
  } else {
    // Handler error
    console.error('Processing error:', error);
    res.status(500).send('Processing failed');
  }
}
```

### Common Error Scenarios

- **Invalid Signature**: Wrong secret or corrupted payload
- **Expired Timestamp**: Request older than tolerance window
- **Unknown Provider**: No matching provider found
- **Missing Configuration**: Provider not configured
- **Handler Error**: Exception in your handler code

---

## 📊 Logging

Enable detailed logging for debugging:

```typescript
import { WebhookRouter, createLogger } from 'unified-webhook-router';

const logger = createLogger({
  level: 'debug',
  format: 'json'
});

const router = new WebhookRouter(config, logger);

// Logs include:
// - Incoming webhook identification
// - Verification success/failure  
// - Handler execution
// - Performance metrics
```

---

## 🎭 Framework Integration Tips

### Getting Raw Body

Most frameworks parse request bodies by default, but webhook verification requires the raw bytes:

```typescript
// Express: Use raw middleware
app.use('/webhooks', express.raw({ type: '*/*' }));

// Next.js: Disable body parser
export const config = { api: { bodyParser: false } };

// Koa: Use raw-body middleware
app.use(bodyParser({ enableTypes: ['text'] }));
```

### CORS and Headers

```typescript
// If needed, configure CORS for webhook endpoints
app.use('/webhooks', cors({
  origin: false, // Webhooks don't need CORS
  credentials: false
}));
```

### Rate Limiting

```typescript
// Protect webhook endpoints from abuse
app.use('/webhooks', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
}));
```

---

## 🧪 Testing

### Unit Testing

```typescript
import { WebhookRouter } from 'unified-webhook-router';

describe('Webhook Handlers', () => {
  const router = new WebhookRouter({
    stripe: { signingSecret: 'test_secret' }
  });

  it('handles payment success', async () => {
    const mockEvent = router.createTestEvent('stripe', 'payment_intent.succeeded', {
      id: 'pi_test',
      amount: 1000
    });

    const result = await myPaymentHandler(mockEvent);
    expect(result).toBeDefined();
  });
});
```

### Integration Testing

```typescript
// Test with real webhook payloads
const stripePayload = JSON.stringify({
  id: 'evt_test',
  type: 'payment_intent.succeeded',
  data: { object: { id: 'pi_test', amount: 1000 } }
});

const signature = generateStripeSignature(stripePayload, secret);

const mockReq = {
  headers: { 'stripe-signature': signature },
  body: Buffer.from(stripePayload)
};

await router.handle(mockReq, mockRes);
```

---

## ⚡ Performance Tips

### Optimize for High Throughput

```typescript
// Use connection pooling for database operations
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

router.on('stripe', 'payment_intent.succeeded', async (event) => {
  const client = await pool.connect();
  try {
    await client.query('INSERT INTO payments ...', [event.payload.id]);
  } finally {
    client.release();
  }
});

// Use queues for heavy processing
router.on('github', 'push', async (event) => {
  await queue.add('deploy', {
    repository: event.payload.repository.full_name,
    commit: event.payload.head_commit.id
  });
});
```

### Memory Management

```typescript
// Avoid storing large objects in memory
router.on('stripe', 'invoice.finalized', async (event) => {
  // Process immediately, don't store
  await generateInvoicePDF(event.payload);
  
  // Or queue for later processing
  await queue.add('invoice-pdf', { invoiceId: event.payload.id });
});
```

---

## 🚀 Deployment

### Environment Variables

```bash
# .env file
STRIPE_SIGNING_SECRET=whsec_...
GITHUB_WEBHOOK_SECRET=your_github_secret
SLACK_SIGNING_SECRET=your_slack_secret
TWILIO_AUTH_TOKEN=your_twilio_token
SQUARE_SIGNATURE_KEY=your_square_key
SQUARE_NOTIFICATION_URL=https://yourdomain.com/webhooks
```

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: webhook-server
  template:
    metadata:
      labels:
        app: webhook-server
    spec:
      containers:
      - name: webhook-server
        image: your-registry/webhook-server
        ports:
        - containerPort: 3000
        env:
        - name: STRIPE_SIGNING_SECRET
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: stripe-signing-secret
```

---

## 🔍 Troubleshooting

### Common Issues

**"Invalid signature" errors:**
```typescript
// Check if you're using the raw request body
app.use('/webhooks', express.raw({ type: '*/*' })); // ✅ Correct
app.use('/webhooks', express.json()); // ❌ Wrong - parses body
```

**Timestamp tolerance errors:**
```typescript
// Increase tolerance if needed (max recommended: 600 seconds)
const router = new WebhookRouter({
  stripe: { 
    signingSecret: process.env.STRIPE_SIGNING_SECRET,
    tolerance: 600 // 10 minutes
  }
});
```

**Headers not found:**
```typescript
// Ensure headers are lowercase
const normalizedHeaders = Object.fromEntries(
  Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
);
```

### Debug Mode

```typescript
const router = new WebhookRouter(config, {
  debug: true, // Enable verbose logging
  logLevel: 'debug'
});
```

### Health Checks

```typescript
// Add a health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    providers: router.getEnabledProviders(),
    uptime: process.uptime()
  });
});
```

---

## 🤝 Contributing

We love contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-provider`
3. **Add your changes** with tests
4. **Run the test suite**: `npm test` or `pytest`
5. **Submit a pull request**

### Adding a New Provider

1. Create provider implementation in `src/providers/`
2. Add comprehensive tests
3. Update documentation
4. Submit PR with example usage

---

## 📄 License

MIT © [Your Name]

---

## 🙏 Acknowledgments

Built with inspiration from the webhook handling challenges faced by developers everywhere. Special thanks to:

- The security teams at Stripe, GitHub, Slack, and others for their excellent documentation
- The Node.js and Python communities for building robust crypto libraries
- Every developer who's ever struggled with webhook verification

---

## 🔗 Links

- **Documentation**: [docs.example.com](https://docs.example.com)
- **GitHub**: [github.com/username/unified-webhook-router](https://github.com/username/unified-webhook-router)
- **NPM**: [npmjs.com/package/unified-webhook-router](https://npmjs.com/package/unified-webhook-router)
- **PyPI**: [pypi.org/project/unified-webhook-router](https://pypi.org/project/unified-webhook-router)
- **Issues**: [github.com/username/unified-webhook-router/issues](https://github.com/username/unified-webhook-router/issues)

---

**Made with ❤️ for developers who deserve better webhook handling.**