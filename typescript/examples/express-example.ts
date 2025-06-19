import express from 'express';
import { WebhookRouter } from '../src';

const app = express();

// Initialize the webhook router with provider configurations
const router = new WebhookRouter({
  stripe: { 
    signingSecret: process.env.STRIPE_SIGNING_SECRET || '' 
  },
  github: { 
    secret: process.env.GITHUB_WEBHOOK_SECRET || '',
    algorithm: 'sha256'
  },
  slack: { 
    signingSecret: process.env.SLACK_SIGNING_SECRET || '' 
  },
  twilio: { 
    authToken: process.env.TWILIO_AUTH_TOKEN || '' 
  },
  square: { 
    signatureKey: process.env.SQUARE_SIGNATURE_KEY || '',
    notificationUrl: 'https://example.com/webhooks'
  }
});

// Register webhook handlers
router.on('stripe', 'checkout.session.completed', async (event) => {
  console.log('Stripe checkout completed:', event.payload.id);
  // Process the checkout session
});

router.on('stripe', 'payment_intent.succeeded', async (event) => {
  console.log('Stripe payment succeeded:', event.payload.id);
  // Process the payment
});

router.on('github', 'push', async (event) => {
  const repo = event.payload.repository.full_name;
  const commits = event.payload.commits.length;
  console.log(`GitHub push to ${repo}: ${commits} commits`);
  // Trigger CI/CD pipeline
});

router.on('github', 'pull_request', async (event) => {
  console.log('GitHub PR event:', event.payload.action);
  // Handle pull request event
});

router.on('slack', '/deploy', async (event) => {
  const user = event.payload.user_name;
  console.log(`Slack command /deploy invoked by ${user}`);
  // Return a response to Slack
  return {
    text: `Deployment started by ${user}!`,
    response_type: 'in_channel'
  };
});

router.on('twilio', 'message.received', async (event) => {
  console.log('SMS received from:', event.payload.From);
  console.log('Message:', event.payload.Body);
  // Process incoming SMS
});

router.on('square', 'payment.updated', async (event) => {
  console.log('Square payment updated:', event.payload.payment.id);
  // Update payment status
});

// Wildcard handler for all unhandled Stripe events
router.on('stripe', '*', async (event) => {
  console.log('Unhandled Stripe event:', event.type);
});

// Set up the webhook endpoint
// Important: Use raw body parser for webhook signature verification
app.post('/webhooks', express.raw({ type: '*/*' }), (req, res) => {
  router.handle(req, res);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Webhook server listening on port ${PORT}`);
});